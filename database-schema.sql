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

-- Create habits table (daily habits only)
CREATE TABLE IF NOT EXISTS habits (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  category VARCHAR(100), -- category/tag for filtering
  color VARCHAR(7) DEFAULT '#3B82F6', -- hex color for UI
  current_streak INTEGER DEFAULT 0, -- current consecutive days
  longest_streak INTEGER DEFAULT 0, -- longest streak ever achieved
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create habit_logs table for tracking daily completions
CREATE TABLE IF NOT EXISTS habit_logs (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  habit_id UUID NOT NULL REFERENCES habits(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  completed_date DATE NOT NULL, -- date of completion (YYYY-MM-DD)
  notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(habit_id, completed_date) -- one completion per day per habit
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_habits_user_id ON habits(user_id);
CREATE INDEX IF NOT EXISTS idx_habits_active ON habits(is_active);
CREATE INDEX IF NOT EXISTS idx_habits_category ON habits(category);
CREATE INDEX IF NOT EXISTS idx_habits_user_category ON habits(user_id, category);
CREATE INDEX IF NOT EXISTS idx_habit_logs_habit_id ON habit_logs(habit_id);
CREATE INDEX IF NOT EXISTS idx_habit_logs_user_id ON habit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_habit_logs_completed_date ON habit_logs(completed_date);
CREATE INDEX IF NOT EXISTS idx_habit_logs_habit_date ON habit_logs(habit_id, completed_date);

-- Enable RLS for habits
ALTER TABLE habits ENABLE ROW LEVEL SECURITY;
ALTER TABLE habit_logs ENABLE ROW LEVEL SECURITY;

-- Policies for habits table
CREATE POLICY "Service role can manage habits" ON habits
  FOR ALL USING (
    current_setting('request.jwt.claims', true)::json->>'role' = 'service_role'
  );

CREATE POLICY "Users can manage their own habits" ON habits
  FOR ALL USING (user_id = auth.uid());

-- Policies for habit_logs table
CREATE POLICY "Service role can manage habit logs" ON habit_logs
  FOR ALL USING (
    current_setting('request.jwt.claims', true)::json->>'role' = 'service_role'
  );

CREATE POLICY "Users can manage their own habit logs" ON habit_logs
  FOR ALL USING (user_id = auth.uid());
-- Create habit_shares table for public sharing
CREATE TABLE IF NOT EXISTS habit_shares (
  id VARCHAR(32) PRIMARY KEY, -- hex string for share ID
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  settings JSONB NOT NULL, -- share settings (theme, username, etc.)
  habits JSONB NOT NULL, -- array of habit data to share
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  view_count INTEGER DEFAULT 0
);

-- Create indexes for habit_shares
CREATE INDEX IF NOT EXISTS idx_habit_shares_user_id ON habit_shares(user_id);
CREATE INDEX IF NOT EXISTS idx_habit_shares_expires_at ON habit_shares(expires_at);

-- Enable RLS for habit_shares
ALTER TABLE habit_shares ENABLE ROW LEVEL SECURITY;

-- Policies for habit_shares table
CREATE POLICY "Service role can manage habit shares" ON habit_shares
  FOR ALL USING (
    current_setting('request.jwt.claims', true)::json->>'role' = 'service_role'
  );

-- Allow public read access to non-expired shares
CREATE POLICY "Public can read non-expired shares" ON habit_shares
  FOR SELECT USING (expires_at > NOW());

-- Users can manage their own shares
CREATE POLICY "Users can manage their own shares" ON habit_shares
  FOR ALL USING (user_id = auth.uid());

-- Create function to clean up expired shares (optional)
CREATE OR REPLACE FUNCTION cleanup_expired_shares()
RETURNS void AS $$$
BEGIN
  DELETE FROM habit_shares WHERE expires_at < NOW() - INTERVAL '7 days';
END;
$$$ LANGUAGE plpgsql;

-- Create a scheduled job to run cleanup (you can set this up in Supabase dashboard)
-- SELECT cron.schedule('cleanup-expired-shares', '0 2 * * *', 'SELECT cleanup_expired_shares();');