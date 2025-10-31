-- Create users table in Supabase
-- Run this SQL in your Supabase SQL editor

CREATE TABLE IF NOT EXISTS users (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  name VARCHAR(255) NOT NULL,
  password VARCHAR(255), -- NULL for Google OAuth users
  google_id VARCHAR(255) UNIQUE, -- NULL for email/password users
  avatar TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create an index on email for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Create an index on google_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);

-- Option 1: Disable RLS for custom auth system (simpler approach)
-- ALTER TABLE users DISABLE ROW LEVEL SECURITY;

-- Option 2: Enable RLS with policies for service role (recommended)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Allow service role to do everything (backend operations)
CREATE POLICY "Service role can manage users" ON users
  FOR ALL USING (
    current_setting('request.jwt.claims', true)::json->>'role' = 'service_role'
  );

-- Allow anon role to insert new users (for registration)
CREATE POLICY "Allow user registration" ON users
  FOR INSERT WITH CHECK (true);

-- Allow anon role to select users for authentication
CREATE POLICY "Allow user authentication" ON users
  FOR SELECT USING (true);

-- Note: Using service role key in backend bypasses RLS entirely
-- These policies are backup for anon key operations