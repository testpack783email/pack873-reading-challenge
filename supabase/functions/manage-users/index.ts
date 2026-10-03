import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

const allowedDenNames = new Set([
  "Lion",
  "Tiger",
  "Wolf",
  "Bear",
  "Webelos",
  "Arrow of Light",
]);

function reply(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
    },
  });
}

async function sendTemporaryPasswordEmail(input: {
  to: string;
  name: string;
  temporaryPassword: string;
  event: "created" | "reactivated";
}): Promise<boolean> {
  const bridgeUrl = Deno.env.get("GMAIL_BRIDGE_URL");
  const bridgeSecret = Deno.env.get("GMAIL_BRIDGE_SECRET");

  if (!bridgeUrl || !bridgeSecret || !input.to) {
    return false;
  }

  try {
    const endpoint = new URL(bridgeUrl);
    if (endpoint.protocol !== "https:") {
      return false;
    }

    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        secret: bridgeSecret,
        to: input.to,
        name: input.name,
        tempPassword: input.temporaryPassword,
        event: input.event,
      }),
    });

    const raw = await response.text();
    let result: { success?: boolean } = {};
    try {
      result = raw ? JSON.parse(raw) : {};
    } catch {
      return false;
    }

    return response.ok && result.success === true;
  } catch {
    // Never log the request body, temporary password, or bridge secret.
    return false;
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return reply({ error: "Not authenticated" }, 401);
    }

    // The privileged client remains server-side and verifies the caller token.
    const adminClient = createClient(supabaseUrl, serviceRoleKey);
    const token = authHeader.replace(/^Bearer\s+/i, "");
    const {
      data: { user },
      error: userError,
    } = await adminClient.auth.getUser(token);

    if (userError || !user) {
      return reply({ error: "Invalid login session" }, 401);
    }

    const { data: profile, error: profileError } = await adminClient
      .from("profiles")
      .select("id, display_name, role, active, must_change_password")
      .eq("id", user.id)
      .single();

    if (profileError || !profile || profile.active !== true) {
      return reply({ error: "Admin access required" }, 403);
    }

    const body = await req.json();
    const action = body.action;

    // Any active signed-in user can change their own password, including a
    // new/reactivated user who is blocked from all other app operations below.
    if (action === "change-password") {
      const newPassword = String(body.new_password || "");
      if (newPassword.length < 8) {
        return reply({ error: "New password must be at least 8 characters" }, 400);
      }

      const { error: passwordError } = await adminClient.auth.admin.updateUserById(
        user.id,
        { password: newPassword },
      );
      if (passwordError) {
        return reply({ error: passwordError.message }, 400);
      }

      const { error: updateError } = await adminClient
        .from("profiles")
        .update({ must_change_password: false })
        .eq("id", user.id);
      if (updateError) {
        return reply(
          {
            error:
              "The password changed, but the account flag could not be cleared. Submit the same new password again to retry.",
          },
          500,
        );
      }

      return reply({
        success: true,
        message: "Your password has been changed",
      });
    }

    if (profile.must_change_password === true) {
      return reply({ error: "Change your temporary password before continuing" }, 403);
    }

    // All remaining actions are restricted to active Pack 873 Admins.
    if (profile.role !== "admin") {
      return reply({ error: "Admin access required" }, 403);
    }

    // Existing connection test.
    if (action === "test") {
      return reply({
        success: true,
        message: "Pack 873 Admin verified",
        admin: profile.display_name,
      });
    }

    if (action === "list-users") {
      const { data: authData, error: authError } =
        await adminClient.auth.admin.listUsers({ page: 1, perPage: 1000 });
      if (authError) {
        return reply({ error: authError.message }, 400);
      }

      const profileWithDen = await adminClient
        .from("profiles")
        .select("id, display_name, role, active, must_change_password, den_name");
      let profileData = profileWithDen.data;
      let listProfileError = profileWithDen.error;
      // Keep older deployments usable until the den_name migration has run.
      if (listProfileError?.message.toLowerCase().includes("den_name")) {
        const legacyProfiles = await adminClient
          .from("profiles")
          .select("id, display_name, role, active, must_change_password");
        profileData = legacyProfiles.data;
        listProfileError = legacyProfiles.error;
      }
      if (listProfileError) {
        return reply({ error: listProfileError.message }, 400);
      }

      const profilesById = new Map(
        (profileData || []).map((item) => [item.id, item]),
      );
      const users = (authData.users || []).map((authUser) => {
        const listedProfile = profilesById.get(authUser.id);
        return {
          id: authUser.id,
          display_name: listedProfile?.display_name || "",
          role: listedProfile?.role || "user",
          active: listedProfile?.active !== false,
          must_change_password: listedProfile?.must_change_password === true,
          den_name: listedProfile?.den_name || "",
          email: authUser.email || "",
        };
      });

      return reply({ success: true, users });
    }

    // Create a new Pack 873 user using the server-only standard password.
    if (action === "create-user") {
      const displayName = String(body.display_name || "").trim();
      const email = String(body.email || "").trim().toLowerCase();
      const denName = String(body.den_name || "").trim();
      if (body.role === "admin") {
        return reply(
          { error: "This app is configured for one Admin. New accounts must use the User role." },
          409,
        );
      }
      const role = "user";
      const temporaryPassword = Deno.env.get("STANDARD_TEMP_PASSWORD");

      if (!displayName || !email || (role === "user" && !denName)) {
        return reply(
          { error: role === "user" ? "Name, email, and Ranks are required" : "Name and email are required" },
          400,
        );
      }
      if (role === "user" && !allowedDenNames.has(denName)) {
        return reply({ error: "Choose a valid Ranks option" }, 400);
      }
      if (!temporaryPassword || temporaryPassword.length < 8) {
        return reply(
          { error: "The standard temporary password is not configured on the server" },
          503,
        );
      }

      const { data: created, error: createError } =
        await adminClient.auth.admin.createUser({
          email,
          password: temporaryPassword,
          email_confirm: true,
        });
      if (createError || !created.user) {
        return reply(
          { error: createError?.message || "Could not create authentication user" },
          400,
        );
      }

      const { error: insertError } = await adminClient.from("profiles").insert({
        id: created.user.id,
        display_name: displayName,
        den_name: role === "user" ? denName : null,
        role,
        active: true,
        must_change_password: true,
      });
      if (insertError) {
        await adminClient.auth.admin.deleteUser(created.user.id);
        return reply(
          {
            error:
              "Authentication account was created, but the profile could not be created: " +
              insertError.message,
          },
          500,
        );
      }

      const emailSent = await sendTemporaryPasswordEmail({
        to: email,
        name: displayName,
        temporaryPassword,
        event: "created",
      });

      return reply({
        success: true,
        email_sent: emailSent,
        message: emailSent
          ? `${displayName} created successfully. A temporary-password email was sent to ${email}. They must change it at first sign-in.`
          : `${displayName} was created, but the email could not be sent. Share the standard temporary password privately; they must change it at first sign-in.`,
        user: {
          id: created.user.id,
          display_name: displayName,
          den_name: role === "user" ? denName : null,
          email,
          role,
          active: true,
        },
      });
    }

    // Deactivate a Pack 873 user. Their reading data remains in place.
    if (action === "deactivate-user") {
      const targetUserId = String(body.user_id || "");
      if (!targetUserId) {
        return reply({ error: "User ID is required" }, 400);
      }
      if (targetUserId === user.id) {
        return reply({ error: "You cannot deactivate your own Admin account" }, 400);
      }

      const { data: updatedProfile, error } = await adminClient
        .from("profiles")
        .update({ active: false })
        .eq("id", targetUserId)
        .neq("role", "admin")
        .select("id")
        .maybeSingle();
      if (error) {
        return reply({ error: error.message }, 400);
      }
      if (!updatedProfile) {
        return reply(
          { error: "User was not found or Admin accounts cannot be deactivated" },
          409,
        );
      }

      return reply({ success: true, message: "User deactivated successfully" });
    }

    // Reactivation resets the Auth password and requires it to be changed.
    if (action === "reactivate-user") {
      const targetUserId = String(body.user_id || "");
      if (!targetUserId) {
        return reply({ error: "User ID is required" }, 400);
      }
      const { data: targetProfile, error: targetProfileError } = await adminClient
        .from("profiles")
        .select("id, role, display_name")
        .eq("id", targetUserId)
        .maybeSingle();
      if (targetProfileError) {
        return reply({ error: targetProfileError.message }, 400);
      }
      if (!targetProfile) {
        return reply({ error: "User was not found" }, 404);
      }
      if (targetProfile.role === "admin") {
        return reply({ error: "The app is configured for one Admin; Admin accounts cannot be reactivated here" }, 409);
      }

      let targetEmail = "";
      try {
        const { data: { user: targetAuthUser }, error: targetAuthError } =
          await adminClient.auth.admin.getUserById(targetUserId);
        if (!targetAuthError) {
          targetEmail = targetAuthUser?.email || "";
        }
      } catch {
        // Reactivation can still proceed; the Admin will get a delivery fallback.
      }

      const temporaryPassword = Deno.env.get("STANDARD_TEMP_PASSWORD");
      if (!temporaryPassword || temporaryPassword.length < 8) {
        return reply(
          { error: "The standard temporary password is not configured on the server" },
          503,
        );
      }

      const { error: passwordError } = await adminClient.auth.admin.updateUserById(
        targetUserId,
        { password: temporaryPassword },
      );
      if (passwordError) {
        return reply({ error: passwordError.message }, 400);
      }

      const { error } = await adminClient
        .from("profiles")
        .update({ active: true, must_change_password: true })
        .eq("id", targetUserId);
      if (error) {
        return reply(
          {
            error:
              "The password was reset, but the account could not be reactivated. Retry Reactivate User.",
          },
          500,
        );
      }

      const emailSent = await sendTemporaryPasswordEmail({
        to: targetEmail,
        name: targetProfile.display_name || targetEmail.split("@")[0] || "Scout",
        temporaryPassword,
        event: "reactivated",
      });

      return reply({
        success: true,
        email_sent: emailSent,
        message: emailSent
          ? `User reactivated successfully. A temporary-password email was sent to ${targetEmail}. They must change it at first sign-in.`
          : "User was reactivated, but the email could not be sent. Share the standard temporary password privately; they must change it at first sign-in.",
      });
    }

    // Permanently delete a Pack 873 user. Auth deletion cascades through the
    // existing profile and reading-entry relationships, as in the current code.
    if (action === "delete-user") {
      const targetUserId = String(body.user_id || "").trim();
      if (!targetUserId) {
        return reply({ error: "User ID is required" }, 400);
      }
      if (targetUserId === user.id) {
        return reply(
          { error: "You cannot permanently delete your own Admin account" },
          400,
        );
      }

      const { data: targetProfile, error: targetError } = await adminClient
        .from("profiles")
        .select("id, display_name, role, active")
        .eq("id", targetUserId)
        .single();
      if (targetError || !targetProfile) {
        return reply({ error: "User was not found" }, 404);
      }
      if (targetProfile.role === "admin") {
        return reply({ error: "Admin accounts cannot be permanently deleted here" }, 400);
      }
      if (targetProfile.active !== true) {
        return reply(
          { error: "Reactivate this user before permanently deleting the account" },
          400,
        );
      }

      const { error: deleteError } = await adminClient.auth.admin.deleteUser(targetUserId);
      if (deleteError) {
        return reply({ error: deleteError.message }, 400);
      }

      return reply({
        success: true,
        message: `${targetProfile.display_name} was permanently deleted`,
      });
    }

    return reply({ error: "Unknown action" }, 400);
  } catch (error) {
    return reply(
      { error: error instanceof Error ? error.message : "Server error" },
      500,
    );
  }
});

