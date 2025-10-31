const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

async function testConnection() {
  console.log('🔍 Testing Supabase connection...\n');

  // Check environment variables
  console.log('Environment Variables:');
  console.log('- SUPABASE_URL:', process.env.SUPABASE_URL ? '✅ Set' : '❌ Missing');
  console.log('- SUPABASE_ANON_KEY:', process.env.SUPABASE_ANON_KEY ? '✅ Set' : '❌ Missing');
  console.log('- JWT_SECRET:', process.env.JWT_SECRET ? '✅ Set' : '❌ Missing');
  console.log('- SESSION_SECRET:', process.env.SESSION_SECRET ? '✅ Set' : '❌ Missing');
  console.log();

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY) {
    console.log('❌ Please set up your Supabase credentials in the .env file');
    console.log('See setup-guide.md for instructions');
    return;
  }

  try {
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY
    );

    // Test connection by trying to query the users table
    const { data, error } = await supabase
      .from('users')
      .select('count')
      .limit(1);

    if (error) {
      if (error.message.includes('relation "users" does not exist')) {
        console.log('❌ Users table not found');
        console.log('Please run the SQL from backend/database-schema.sql in your Supabase SQL editor');
      } else {
        console.log('❌ Database error:', error.message);
      }
    } else {
      console.log('✅ Supabase connection successful!');
      console.log('✅ Users table exists and is accessible');
    }
  } catch (error) {
    console.log('❌ Connection failed:', error.message);
  }
}

testConnection();