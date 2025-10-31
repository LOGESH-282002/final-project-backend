const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Initialize Supabase client
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
);

async function testShareDatabase() {
    console.log('🧪 Testing habit shares database...');

    try {
        // Test creating a share
        const testShare = {
            id: 'test-share-123',
            user_id: '00000000-0000-0000-0000-000000000000', // dummy UUID
            settings: {
                theme: 'light',
                showUsername: true,
                username: 'TestUser',
                showBestStreak: true,
                showHabitNames: true
            },
            habits: [
                {
                    id: 1,
                    title: 'Morning Exercise',
                    current_streak: 15,
                    longest_streak: 25
                },
                {
                    id: 2,
                    title: 'Read Daily',
                    current_streak: 8,
                    longest_streak: 30
                }
            ],
            created_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
        };

        console.log('Creating test share...');
        const { data: createData, error: createError } = await supabase
            .from('habit_shares')
            .insert([testShare])
            .select();

        if (createError) {
            console.error('❌ Error creating share:', createError);
            return;
        }

        console.log('✅ Share created successfully:', createData[0].id);

        // Test retrieving the share
        console.log('Retrieving test share...');
        const { data: retrieveData, error: retrieveError } = await supabase
            .from('habit_shares')
            .select('*')
            .eq('id', testShare.id)
            .single();

        if (retrieveError) {
            console.error('❌ Error retrieving share:', retrieveError);
            return;
        }

        console.log('✅ Share retrieved successfully');
        console.log('Settings:', retrieveData.settings);
        console.log('Habits count:', retrieveData.habits.length);

        // Clean up test data
        console.log('Cleaning up test data...');
        const { error: deleteError } = await supabase
            .from('habit_shares')
            .delete()
            .eq('id', testShare.id);

        if (deleteError) {
            console.error('❌ Error cleaning up:', deleteError);
            return;
        }

        console.log('✅ Test data cleaned up');
        console.log('🎉 All tests passed! Share database is working correctly.');

    } catch (error) {
        console.error('❌ Test failed:', error);
    }
}

// Run the test
testShareDatabase();