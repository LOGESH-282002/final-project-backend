const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

async function setupStorage() {
    console.log('🔧 Setting up Supabase Storage...\n');

    if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
        console.log('❌ Missing Supabase credentials');
        console.log('Please ensure SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are set in your .env file');
        return;
    }

    // Use service role key for admin operations
    const supabase = createClient(
        process.env.SUPABASE_URL,
        process.env.SUPABASE_SERVICE_ROLE_KEY
    );

    try {
        // Create avatars bucket
        const { data: bucket, error: bucketError } = await supabase.storage
            .createBucket('avatars', {
                public: true,
                allowedMimeTypes: ['image/png', 'image/jpeg', 'image/gif', 'image/webp'],
                fileSizeLimit: 5242880 // 5MB
            });

        if (bucketError) {
            if (bucketError.message.includes('already exists')) {
                console.log('✅ Avatars bucket already exists');
            } else {
                console.log('❌ Error creating bucket:', bucketError.message);
                return;
            }
        } else {
            console.log('✅ Avatars bucket created successfully');
        }

        // Set up RLS policies for the bucket
        console.log('🔒 Setting up storage policies...');
        
        // Note: Storage policies are typically set up in the Supabase dashboard
        // or via SQL. The JavaScript client doesn't have direct policy creation methods.
        
        console.log('\n📋 Manual Setup Required:');
        console.log('1. Go to your Supabase dashboard');
        console.log('2. Navigate to Storage > Policies');
        console.log('3. Create the following policies for the "avatars" bucket:');
        console.log('');
        console.log('Policy 1: "Users can upload their own avatars"');
        console.log('- Operation: INSERT');
        console.log('- Target roles: authenticated');
        console.log('- Policy definition: (storage.foldername(name))[1] = auth.uid()::text');
        console.log('');
        console.log('Policy 2: "Users can update their own avatars"');
        console.log('- Operation: UPDATE');
        console.log('- Target roles: authenticated');
        console.log('- Policy definition: (storage.foldername(name))[1] = auth.uid()::text');
        console.log('');
        console.log('Policy 3: "Users can delete their own avatars"');
        console.log('- Operation: DELETE');
        console.log('- Target roles: authenticated');
        console.log('- Policy definition: (storage.foldername(name))[1] = auth.uid()::text');
        console.log('');
        console.log('Policy 4: "Anyone can view avatars"');
        console.log('- Operation: SELECT');
        console.log('- Target roles: public');
        console.log('- Policy definition: true');
        console.log('');
        console.log('✅ Storage setup completed!');
        console.log('🔗 Your avatars will be accessible at:');
        console.log(`${process.env.SUPABASE_URL}/storage/v1/object/public/avatars/`);

    } catch (error) {
        console.log('❌ Setup failed:', error.message);
    }
}

setupStorage();