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

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// HABITS CRUD OPERATIONS

// Get all habits for the authenticated user with recent completion history
app.get('/api/habits', authenticateToken, async (req, res) => {
    try {
        // Get habits
        const { data: habits, error: habitsError } = await supabase
            .from('habits')
            .select('*')
            .eq('user_id', req.user.id)
            .order('created_at', { ascending: false });

        if (habitsError) {
            console.error('Error fetching habits:', habitsError);
            return res.status(500).json({ error: 'Failed to fetch habits' });
        }

        // Get last 60 days of completions for all habits (to support calendar view)
        const sixtyDaysAgo = new Date();
        sixtyDaysAgo.setDate(sixtyDaysAgo.getDate() - 60);
        const startDate = sixtyDaysAgo.toISOString().split('T')[0];

        const { data: recentLogs, error: logsError } = await supabase
            .from('habit_logs')
            .select('habit_id, completed_date, notes')
            .eq('user_id', req.user.id)
            .gte('completed_date', startDate)
            .order('completed_date', { ascending: false });

        if (logsError) {
            console.error('Error fetching recent logs:', logsError);
            return res.status(500).json({ error: 'Failed to fetch completion history' });
        }

        // Attach recent logs to each habit
        const habitsWithHistory = habits.map(habit => ({
            ...habit,
            recent_completions: recentLogs.filter(log => log.habit_id === habit.id)
        }));

        res.json({ habits: habitsWithHistory });
    } catch (error) {
        console.error('Error fetching habits:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get a single habit by ID
app.get('/api/habits/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        const { data: habit, error } = await supabase
            .from('habits')
            .select(`
                *,
                habit_logs (
                    id,
                    completed_at,
                    notes
                )
            `)
            .eq('id', id)
            .eq('user_id', req.user.id)
            .single();

        if (error || !habit) {
            return res.status(404).json({ error: 'Habit not found' });
        }

        res.json({ habit });
    } catch (error) {
        console.error('Error fetching habit:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create a new habit (daily only)
app.post('/api/habits', authenticateToken, async (req, res) => {
    try {
        const { title, description, category, color } = req.body;

        if (!title) {
            return res.status(400).json({ error: 'Title is required' });
        }

        const { data: habit, error } = await supabase
            .from('habits')
            .insert([
                {
                    user_id: req.user.id,
                    title: title.trim(),
                    description: description?.trim() || null,
                    category: category?.trim() || null,
                    color: color || '#3B82F6',
                    current_streak: 0,
                    longest_streak: 0,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                }
            ])
            .select()
            .single();

        if (error) {
            console.error('Error creating habit:', error);
            return res.status(500).json({ error: 'Failed to create habit' });
        }

        res.status(201).json({
            message: 'Habit created successfully',
            habit
        });
    } catch (error) {
        console.error('Error creating habit:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update a habit
app.put('/api/habits/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, category, color, is_active } = req.body;

        // Verify habit belongs to user
        const { data: existingHabit, error: fetchError } = await supabase
            .from('habits')
            .select('id')
            .eq('id', id)
            .eq('user_id', req.user.id)
            .single();

        if (fetchError || !existingHabit) {
            return res.status(404).json({ error: 'Habit not found' });
        }

        const updateData = {
            updated_at: new Date().toISOString()
        };

        if (title !== undefined) updateData.title = title.trim();
        if (description !== undefined) updateData.description = description?.trim() || null;
        if (category !== undefined) updateData.category = category?.trim() || null;
        if (color !== undefined) updateData.color = color;
        if (is_active !== undefined) updateData.is_active = is_active;

        const { data: habit, error } = await supabase
            .from('habits')
            .update(updateData)
            .eq('id', id)
            .eq('user_id', req.user.id)
            .select()
            .single();

        if (error) {
            console.error('Error updating habit:', error);
            return res.status(500).json({ error: 'Failed to update habit' });
        }

        res.json({
            message: 'Habit updated successfully',
            habit
        });
    } catch (error) {
        console.error('Error updating habit:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete a habit (soft delete by setting is_active to false)
app.delete('/api/habits/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        // Verify habit belongs to user
        const { data: existingHabit, error: fetchError } = await supabase
            .from('habits')
            .select('id')
            .eq('id', id)
            .eq('user_id', req.user.id)
            .single();

        if (fetchError || !existingHabit) {
            return res.status(404).json({ error: 'Habit not found' });
        }

        const { error } = await supabase
            .from('habits')
            .update({
                is_active: false,
                updated_at: new Date().toISOString()
            })
            .eq('id', id)
            .eq('user_id', req.user.id);

        if (error) {
            console.error('Error deleting habit:', error);
            return res.status(500).json({ error: 'Failed to delete habit' });
        }

        res.json({ message: 'Habit deleted successfully' });
    } catch (error) {
        console.error('Error deleting habit:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Toggle daily habit completion
app.post('/api/habits/:id/toggle', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { date, notes } = req.body;
        
        // Use provided date or today
        const completionDate = date || new Date().toISOString().split('T')[0];

        // Verify habit belongs to user and is active
        const { data: habit, error: fetchError } = await supabase
            .from('habits')
            .select('*')
            .eq('id', id)
            .eq('user_id', req.user.id)
            .single();

        if (fetchError || !habit) {
            return res.status(404).json({ error: 'Habit not found' });
        }

        if (!habit.is_active) {
            return res.status(400).json({ error: 'Cannot toggle completion for inactive habit' });
        }

        // Check if already completed for this date
        const { data: existingLog, error: checkError } = await supabase
            .from('habit_logs')
            .select('id')
            .eq('habit_id', id)
            .eq('user_id', req.user.id)
            .eq('completed_date', completionDate)
            .single();

        let isCompleted = false;
        let message = '';

        if (existingLog) {
            // Remove completion
            const { error: deleteError } = await supabase
                .from('habit_logs')
                .delete()
                .eq('id', existingLog.id);

            if (deleteError) {
                console.error('Error removing completion:', deleteError);
                return res.status(500).json({ error: 'Failed to remove completion' });
            }

            message = 'Habit completion removed';
            isCompleted = false;
        } else {
            // Add completion
            const { error: insertError } = await supabase
                .from('habit_logs')
                .insert([
                    {
                        habit_id: id,
                        user_id: req.user.id,
                        completed_date: completionDate,
                        notes: notes?.trim() || null,
                        created_at: new Date().toISOString()
                    }
                ]);

            if (insertError) {
                console.error('Error adding completion:', insertError);
                return res.status(500).json({ error: 'Failed to add completion' });
            }

            message = 'Habit completion added';
            isCompleted = true;
        }

        // Recalculate streaks
        await calculateStreaks(id, req.user.id);

        res.json({
            message,
            isCompleted,
            date: completionDate
        });
    } catch (error) {
        console.error('Error toggling habit completion:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Helper function to calculate streaks
async function calculateStreaks(habitId, userId) {
    try {
        // Get all completions for this habit, ordered by date
        const { data: logs, error } = await supabase
            .from('habit_logs')
            .select('completed_date')
            .eq('habit_id', habitId)
            .eq('user_id', userId)
            .order('completed_date', { ascending: false });

        if (error) {
            console.error('Error fetching logs for streak calculation:', error);
            return;
        }

        let currentStreak = 0;
        let longestStreak = 0;
        let tempStreak = 0;

        if (logs.length > 0) {
            const today = new Date();
            const todayStr = today.toISOString().split('T')[0];
            const yesterdayStr = new Date(today.getTime() - 24 * 60 * 60 * 1000).toISOString().split('T')[0];

            // Calculate current streak (must include today or yesterday to be current)
            const sortedDates = logs.map(log => log.completed_date).sort((a, b) => new Date(b) - new Date(a));
            
            // Check if streak is current (includes today or yesterday)
            if (sortedDates[0] === todayStr || sortedDates[0] === yesterdayStr) {
                let checkDate = new Date(sortedDates[0]);
                
                for (const dateStr of sortedDates) {
                    const logDate = new Date(dateStr);
                    const expectedDate = checkDate.toISOString().split('T')[0];
                    
                    if (dateStr === expectedDate) {
                        currentStreak++;
                        checkDate.setDate(checkDate.getDate() - 1);
                    } else {
                        break;
                    }
                }
            }

            // Calculate longest streak
            const allDates = sortedDates.sort((a, b) => new Date(a) - new Date(b));
            
            for (let i = 0; i < allDates.length; i++) {
                if (i === 0) {
                    tempStreak = 1;
                } else {
                    const prevDate = new Date(allDates[i - 1]);
                    const currDate = new Date(allDates[i]);
                    const diffDays = Math.floor((currDate - prevDate) / (1000 * 60 * 60 * 24));
                    
                    if (diffDays === 1) {
                        tempStreak++;
                    } else {
                        longestStreak = Math.max(longestStreak, tempStreak);
                        tempStreak = 1;
                    }
                }
            }
            longestStreak = Math.max(longestStreak, tempStreak);
        }

        // Update habit with new streak values
        await supabase
            .from('habits')
            .update({
                current_streak: currentStreak,
                longest_streak: Math.max(longestStreak, currentStreak),
                updated_at: new Date().toISOString()
            })
            .eq('id', habitId)
            .eq('user_id', userId);

    } catch (error) {
        console.error('Error calculating streaks:', error);
    }
}

// Get habit logs for a specific habit
app.get('/api/habits/:id/logs', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { limit = 50, offset = 0 } = req.query;

        // Verify habit belongs to user
        const { data: habit, error: fetchError } = await supabase
            .from('habits')
            .select('id')
            .eq('id', id)
            .eq('user_id', req.user.id)
            .single();

        if (fetchError || !habit) {
            return res.status(404).json({ error: 'Habit not found' });
        }

        const { data: logs, error } = await supabase
            .from('habit_logs')
            .select('*')
            .eq('habit_id', id)
            .eq('user_id', req.user.id)
            .order('completed_at', { ascending: false })
            .range(offset, offset + limit - 1);

        if (error) {
            console.error('Error fetching habit logs:', error);
            return res.status(500).json({ error: 'Failed to fetch habit logs' });
        }

        res.json({ logs });
    } catch (error) {
        console.error('Error fetching habit logs:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete a habit log
app.delete('/api/habits/:habitId/logs/:logId', authenticateToken, async (req, res) => {
    try {
        const { habitId, logId } = req.params;

        // Verify log belongs to user and habit
        const { data: log, error: fetchError } = await supabase
            .from('habit_logs')
            .select('id')
            .eq('id', logId)
            .eq('habit_id', habitId)
            .eq('user_id', req.user.id)
            .single();

        if (fetchError || !log) {
            return res.status(404).json({ error: 'Habit log not found' });
        }

        const { error } = await supabase
            .from('habit_logs')
            .delete()
            .eq('id', logId)
            .eq('user_id', req.user.id);

        if (error) {
            console.error('Error deleting habit log:', error);
            return res.status(500).json({ error: 'Failed to delete habit log' });
        }

        res.json({ message: 'Habit log deleted successfully' });
    } catch (error) {
        console.error('Error deleting habit log:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create public share link
app.post('/api/share/create', authenticateToken, async (req, res) => {
    try {
        const { settings, habits } = req.body;

        // Generate unique share ID
        const shareId = require('crypto').randomBytes(16).toString('hex');
        
        // Store share data in database (you'll need to create this table)
        const shareData = {
            id: shareId,
            user_id: req.user.id,
            settings: settings,
            habits: habits,
            created_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() // 30 days
        };

        // For now, we'll use a simple in-memory storage or file system
        // In production, you'd want to create a 'shares' table in your database
        const { data: share, error } = await supabase
            .from('habit_shares')
            .insert([shareData])
            .select()
            .single();

        if (error) {
            console.error('Error creating share:', error);
            return res.status(500).json({ error: 'Failed to create share link' });
        }

        res.json({
            shareId: shareId,
            shareUrl: `${process.env.CLIENT_URL}/public/${shareId}`
        });
    } catch (error) {
        console.error('Error creating share link:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get public share data
app.get('/api/share/:shareId', async (req, res) => {
    try {
        const { shareId } = req.params;

        const { data: share, error } = await supabase
            .from('habit_shares')
            .select('*')
            .eq('id', shareId)
            .single();

        if (error || !share) {
            return res.status(404).json({ error: 'Share not found' });
        }

        // Check if share has expired
        if (new Date(share.expires_at) < new Date()) {
            return res.status(404).json({ error: 'Share has expired' });
        }

        // Return share data without user info
        res.json({
            settings: share.settings,
            habits: share.habits,
            createdAt: share.created_at
        });
    } catch (error) {
        console.error('Error fetching share data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`🔗 Client URL: ${process.env.CLIENT_URL}`);
    console.log(`🔑 Google OAuth configured: ${!!process.env.GOOGLE_CLIENT_ID}`);
});