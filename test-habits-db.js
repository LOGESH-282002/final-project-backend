const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Initialize Supabase client with service role key
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
);

async function testHabitsDatabase() {
    console.log('🔍 Testing Habits Database Connection...');
    
    try {
        // Test 1: Check if habits table exists
        console.log('\n1. Checking if habits table exists...');
        const { data: habitsTest, error: habitsError } = await supabase
            .from('habits')
            .select('count')
            .limit(1);
        
        if (habitsError) {
            console.log('❌ Habits table does not exist or has issues:', habitsError.message);
            console.log('📝 You need to run the SQL schema in your Supabase dashboard!');
            return;
        } else {
            console.log('✅ Habits table exists');
        }

        // Test 2: Check if habit_logs table exists
        console.log('\n2. Checking if habit_logs table exists...');
        const { data: logsTest, error: logsError } = await supabase
            .from('habit_logs')
            .select('count')
            .limit(1);
        
        if (logsError) {
            console.log('❌ Habit_logs table does not exist or has issues:', logsError.message);
            console.log('📝 You need to run the SQL schema in your Supabase dashboard!');
            return;
        } else {
            console.log('✅ Habit_logs table exists');
        }

        // Test 3: Check users table (should already exist)
        console.log('\n3. Checking users table...');
        const { data: usersTest, error: usersError } = await supabase
            .from('users')
            .select('count')
            .limit(1);
        
        if (usersError) {
            console.log('❌ Users table issue:', usersError.message);
        } else {
            console.log('✅ Users table exists');
        }

        console.log('\n🎉 All database tables are ready for habits CRUD operations!');
        console.log('\n📋 Next steps:');
        console.log('1. Make sure you are logged in to the frontend');
        console.log('2. Navigate to /habits to test the functionality');
        
    } catch (error) {
        console.error('❌ Database test failed:', error);
    }
}

testHabitsDatabase();