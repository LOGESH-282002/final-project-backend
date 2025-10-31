const express = require('express');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();

// Configure multer for file uploads (using memory storage for Supabase)

// Use memory storage for Supabase upload
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit
    },
    fileFilter: (req, file, cb) => {
        // Check if file is an image
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// Validate environment variables
const requiredEnvVars = [
    'SUPABASE_URL',
    'SUPABASE_ANON_KEY',
    'SUPABASE_SERVICE_ROLE_KEY',
    'JWT_SECRET',
    'SESSION_SECRET'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.error('❌ Missing required environment variables:');
    missingVars.forEach(varName => console.log(`- ${varName}`));
    console.log('\nPlease check your .env file and add the missing variables.');
    process.exit(1);
}

if (!process.env.SUPABASE_URL.startsWith('https://')) {
    console.error('❌ Invalid SUPABASE_URL. It should start with https://');
    console.log('Example: https://your-project-id.supabase.co');
    process.exit(1);
}

// Initialize Supabase client with service role key (bypasses RLS)
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY
);

// Middleware
app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);

        const allowedOrigins = [
            'http://localhost:3000',
            'http://localhost:3001',
            process.env.CLIENT_URL,
            // Allow all Vercel preview deployments
            /^https:\/\/.*\.vercel\.app$/
        ].filter(Boolean);

        // Check if origin matches any allowed pattern
        const isAllowed = allowedOrigins.some(allowedOrigin => {
            if (typeof allowedOrigin === 'string') {
                return origin === allowedOrigin || origin === allowedOrigin.replace(/\/$/, '');
            }
            if (allowedOrigin instanceof RegExp) {
                return allowedOrigin.test(origin);
            }
            return false;
        });

        if (isAllowed) {
            callback(null, true);
        } else {
            console.log('CORS blocked origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use HTTPS in production
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// Passport configuration
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // Check if user exists in Supabase
        const { data: existingUser, error } = await supabase
            .from('users')
            .select('*')
            .eq('google_id', profile.id)
            .single();

        if (existingUser) {
            return done(null, existingUser);
        }

        // Create new user in Supabase
        const { data: newUser, error: insertError } = await supabase
            .from('users')
            .insert([
                {
                    google_id: profile.id,
                    email: profile.emails[0].value,
                    name: profile.displayName,
                    avatar: profile.photos[0].value,
                    created_at: new Date().toISOString()
                }
            ])
            .select()
            .single();

        if (insertError) {
            return done(insertError, null);
        }

        return done(null, newUser);
    } catch (error) {
        return done(error, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', id)
            .single();

        if (error) {
            return done(error, null);
        }

        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

// Routes
app.get('/', (req, res) => {
    res.json({ message: 'Authentication API is running!' });
});

// Google OAuth routes
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: `${process.env.CLIENT_URL}/login` }),
    (req, res) => {
        try {
            // Generate JWT token
            const token = jwt.sign(
                {
                    id: req.user.id,
                    email: req.user.email,
                    name: req.user.name
                },
                process.env.JWT_SECRET,
                { expiresIn: '7d' }
            );

            // Redirect to frontend with token
            const redirectUrl = `${process.env.CLIENT_URL}/auth/callback?token=${token}`;
            console.log('Redirecting to:', redirectUrl);
            res.redirect(redirectUrl);
        } catch (error) {
            console.error('OAuth callback error:', error);
            res.redirect(`${process.env.CLIENT_URL}/login?error=oauth_failed`);
        }
    }
);

// Regular email/password registration
app.post('/auth/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;

        if (!email || !password || !name) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Check if user already exists
        const { data: existingUser } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Create user in Supabase
        const { data: newUser, error } = await supabase
            .from('users')
            .insert([
                {
                    email,
                    password: hashedPassword,
                    name,
                    created_at: new Date().toISOString()
                }
            ])
            .select()
            .single();

        if (error) {
            return res.status(500).json({ error: 'Failed to create user' });
        }

        // Generate JWT token
        const token = jwt.sign(
            {
                id: newUser.id,
                email: newUser.email,
                name: newUser.name
            },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            message: 'User created successfully',
            token,
            user: {
                id: newUser.id,
                email: newUser.email,
                name: newUser.name
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Regular email/password login
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        // Find user in Supabase
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check password (only for non-Google users)
        if (user.password) {
            const isValidPassword = await bcrypt.compare(password, user.password);
            if (!isValidPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
        } else {
            return res.status(401).json({ error: 'Please use Google login for this account' });
        }

        // Generate JWT token
        const token = jwt.sign(
            {
                id: user.id,
                email: user.email,
                name: user.name
            },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                avatar: user.avatar
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Logout route
app.post('/auth/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.json({ message: 'Logout successful' });
    });
});

// Get current user
app.get('/auth/me', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const { data: user, error } = await supabase
            .from('users')
            .select('id, email, name, avatar, created_at')
            .eq('id', decoded.id)
            .single();

        if (error || !user) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        res.json({ user });
    } catch (error) {
        console.error('Auth verification error:', error);
        res.status(401).json({ error: 'Invalid token' });
    }
});

// Update user profile
app.put('/auth/profile', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const { name } = req.body;

        if (!name || name.trim().length === 0) {
            return res.status(400).json({ error: 'Name is required' });
        }

        // Update user in Supabase
        const { data: updatedUser, error } = await supabase
            .from('users')
            .update({
                name: name.trim(),
                updated_at: new Date().toISOString()
            })
            .eq('id', decoded.id)
            .select('id, email, name, avatar, created_at')
            .single();

        if (error) {
            console.error('Profile update error:', error);
            return res.status(500).json({ error: 'Failed to update profile' });
        }

        res.json({
            message: 'Profile updated successfully',
            user: updatedUser
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Upload avatar to Supabase Storage
app.post('/auth/upload-avatar', upload.single('avatar'), async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Generate unique filename
        const fileExt = path.extname(req.file.originalname);
        const fileName = `${decoded.id}/avatar-${Date.now()}${fileExt}`;

        // Get current user to check for existing avatar
        const { data: currentUser } = await supabase
            .from('users')
            .select('avatar')
            .eq('id', decoded.id)
            .single();

        // Delete old avatar from Supabase Storage if it exists
        if (currentUser?.avatar) {
            // Extract filename from URL if it's a Supabase Storage URL
            const urlParts = currentUser.avatar.split('/');
            const oldFileName = urlParts[urlParts.length - 1];
            if (oldFileName && oldFileName.includes('avatar-')) {
                const oldFilePath = `${decoded.id}/${oldFileName}`;
                await supabase.storage
                    .from('avatars')
                    .remove([oldFilePath]);
            }
        }

        // Upload file to Supabase Storage (using service role bypasses RLS)
        const { data: uploadData, error: uploadError } = await supabase.storage
            .from('avatars')
            .upload(fileName, req.file.buffer, {
                contentType: req.file.mimetype,
                upsert: true
            });

        // No local file cleanup needed with memory storage

        if (uploadError) {
            console.error('Supabase upload error:', uploadError);
            return res.status(500).json({ error: 'Failed to upload avatar' });
        }

        // Get public URL for the uploaded file
        const { data: urlData } = supabase.storage
            .from('avatars')
            .getPublicUrl(fileName);

        const avatarUrl = urlData.publicUrl;

        // Update user avatar in database
        const { data: updatedUser, error: dbError } = await supabase
            .from('users')
            .update({
                avatar: avatarUrl,
                updated_at: new Date().toISOString()
            })
            .eq('id', decoded.id)
            .select('id, email, name, avatar, created_at')
            .single();

        if (dbError) {
            console.error('Database update error:', dbError);
            // Clean up uploaded file if database update fails
            await supabase.storage
                .from('avatars')
                .remove([fileName]);
            return res.status(500).json({ error: 'Failed to update avatar' });
        }

        res.json({
            message: 'Avatar uploaded successfully',
            user: updatedUser
        });
    } catch (error) {
        console.error('Avatar upload error:', error);
        // No local file cleanup needed with memory storage
        res.status(500).json({ error: 'Internal server error' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`🔗 Client URL: ${process.env.CLIENT_URL}`);
    console.log(`🔑 Google OAuth configured: ${!!process.env.GOOGLE_CLIENT_ID}`);
});