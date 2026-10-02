ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS den_name text;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'profiles_den_name_allowed_values'
      AND conrelid = 'public.profiles'::regclass
  ) THEN
    ALTER TABLE public.profiles
      ADD CONSTRAINT profiles_den_name_allowed_values
      CHECK (
        den_name IS NULL
        OR den_name IN (
          'Lion',
          'Tiger',
          'Wolf',
          'Bear',
          'Webelos',
          'Arrow of Light'
        )
      );
  END IF;
END
$$;
