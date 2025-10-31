const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

async function testStorage() {
    console.log('🔍 Testing Supabase Storage...\n');

    if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
        console.log('❌ Missing Supabase credentials');
        return;
    }

    const supabase = createClient(
        process.env.SUPABASE_URL,
        process.env.SUPABASE_SERVICE_ROLE_KEY
    );

    try {
        // List buckets to verify storage access
        const { data: buckets, error: bucketsError } = await supabase.storage.listBuckets();
        
        if (bucketsError) {
            console.log('❌ Error accessing storage:', bucketsError.message);
            return;
        }

        console.log('📦 Available buckets:');
        buckets.forEach(bucket => {
            console.log(`- ${bucket.name} (${bucket.public ? 'public' : 'private'})`);
        });

        // Check if avatars bucket exists
        const avatarsBucket = buckets.find(bucket => bucket.name === 'avatars');
        if (avatarsBucket) {
            console.log('\n✅ Avatars bucket found and accessible');
            console.log(`🔗 Public URL base: ${process.env.SUPABASE_URL}/storage/v1/object/public/avatars/`);
        } else {
            console.log('\n❌ Avatars bucket not found');
            console.log('Run: npm run setup-storage');
        }

    } catch (error) {
        console.log('❌ Storage test failed:', error.message);
    }
}

testStorage();