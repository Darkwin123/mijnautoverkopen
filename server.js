// server.js
require('dotenv').config();
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const sanitizeHtml = require('sanitize-html');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const connectDB = require('./db'); // Import MongoDB connection

// Import Mongoose Models
const Admin = require('./models/Admin');
const Blog = require('./models/Blog');
const Inquiry = require('./models/Inquiry');

// Connect to MongoDB
connectDB();

// Set up storage configuration for car images
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = process.env.RENDER_DISK_PATH ? path.join(process.env.RENDER_DISK_PATH, 'uploads') : path.join(__dirname, 'public/uploads');
        // Create directory if it doesn't exist
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        // Generate unique filename with original extension
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, 'car-' + uniqueSuffix + ext);
    }
});

// File filter to allow only images
const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Alleen afbeeldingen zijn toegestaan!'), false);
    }
};

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit
        files: 5 // maximum 5 files
    },
    fileFilter: fileFilter
});

const app = express();
const port = process.env.PORT || process.env.RENDER_PORT || 3001;

// Initialize admin
async function initializeAdmin() {
    try {
        const adminCount = await Admin.countDocuments();
        if (adminCount === 0) {
            // Use environment variable or a strong fallback password
            const hashedPassword = await bcrypt.hash(
                process.env.ADMIN_PASSWORD || 'StrongDefaultPassword123!@#', 
                parseInt(process.env.BCRYPT_SALT_ROUNDS || 12)
            );
            
            await Admin.create({
                username: 'admin',
                password: hashedPassword
            });
            
            console.log('Default admin user created');
        }
    } catch (err) {
        console.error('Error creating default admin:', err);
    }
}

// Utility function to create SEO-friendly slug
function createSlug(title) {
    // Convert to lowercase, replace spaces with hyphens, remove special characters
    let slug = title.toLowerCase()
                   .replace(/\s+/g, '-')
                   .replace(/[^\w\-]+/g, '')
                   .replace(/\-\-+/g, '-')
                   .replace(/^-+/, '')
                   .replace(/-+$/, '');
    
    return slug;
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
}

// Utility to ensure categories are applied to all blogs
async function migrateBlogsToAddCategories() {
    try {
        const blogs = await Blog.find({ category: { $exists: false } });
        
        if (blogs.length > 0) {
            for (const blog of blogs) {
                blog.category = "algemeen";
                await blog.save();
            }
            console.log('Migrated blogs to include categories');
        }
    } catch (err) {
        console.error('Error migrating blogs:', err);
    }
}

// Function to get all categories
async function getAllCategories() {
    try {
        const categories = await Blog.distinct('category');
        return categories;
    } catch (err) {
        console.error('Error getting categories:', err);
        return [];
    }
}

function createCategorySlug(categoryName) {
    return categoryName.toLowerCase()
        .replace(/\s+/g, '-')
        .replace(/[^\w\-]+/g, '')
        .replace(/\-\-+/g, '-')
        .replace(/^-+/, '')
        .replace(/-+$/, '');
}

// Add sample blogs if none exist
async function addSampleBlogs() {
    try {
        const blogCount = await Blog.countDocuments();
        
        if (blogCount === 0) {
            const sampleData = [
                {
                    "id": "1678640481000",
                    "title": "De beste tijd om uw auto te verkopen",
                    "slug": "de-beste-tijd-om-uw-auto-te-verkopen",
                    "content": `<p>Het verkopen van een auto kan een strategische beslissing zijn...</p>`,
                    "excerpt": "Ontdek wanneer het financieel gezien het meest voordelig is om uw auto te verkopen, en welke factoren de waarde van uw auto beïnvloeden.",
                    "author": "Autoverkoop Team",
                    "status": "published",
                    "category": "verkoop-tips",
                    "tags": ["verkoop timing", "waardevermindering", "automarkt"],
                    "createdAt": "2023-03-12T18:15:00.000Z",
                    "updatedAt": "2023-03-12T18:15:00.000Z"
                },
                {
                    "id": "1678750481000",
                    "title": "Hoe bereidt u uw auto voor op verkoop?",
                    "slug": "hoe-bereidt-u-uw-auto-voor-op-verkoop",
                    "content": `<p>Een goed voorbereide auto maakt niet alleen een betere indruk...</p>`,
                    "excerpt": "Leer hoe u uw auto optimaal kunt voorbereiden voor verkoop om de hoogste prijs te krijgen en een snelle verkoop te realiseren.",
                    "author": "Autoverkoop Team",
                    "status": "published",
                    "category": "verkoop-tips",
                    "tags": ["voorbereiding", "auto verkopen", "waarde verhogen"],
                    "createdAt": "2023-04-15T14:30:00.000Z",
                    "updatedAt": "2023-04-15T14:30:00.000Z"
                },
                {
                    "id": "1678850481000",
                    "title": "Particulier verkopen of inruilen: wat is voordelig?",
                    "slug": "particulier-verkopen-of-inruilen-wat-is-voordelig",
                    "content": `<p>Wanneer u uw huidige auto wilt vervangen, heeft u verschillende opties...</p>`,
                    "excerpt": "Vergelijk de verschillende manieren om uw auto te verkopen en ontdek welke optie het beste bij uw situatie past.",
                    "author": "Autoverkoop Team",
                    "status": "published",
                    "category": "verkoop-opties",
                    "tags": ["particulier verkopen", "inruilen", "auto inkoop"],
                    "createdAt": "2023-05-20T10:45:00.000Z",
                    "updatedAt": "2023-05-20T10:45:00.000Z"
                }
            ];
            
            await Blog.insertMany(sampleData);
            console.log('Added sample blog data');
        }
    } catch (err) {
        console.error('Error adding sample blogs:', err);
    }
}

// Add sample inquiries if none exist
async function addSampleData() {
    try {
        const inquiryCount = await Inquiry.countDocuments();
        
        if (inquiryCount === 0) {
            const sampleData = [
                {
                    "id": "1678610481000",
                    "kenteken": "AB-123-Z",
                    "merk": "Volkswagen",
                    "model": "Golf",
                    "bouwjaar": 2018,
                    "brandstof": "benzine",
                    "kilometerstand": 85000,
                    "transmissie": "handgeschakeld",
                    "schade": "geen",
                    "apk": "2024-06",
                    "opties": ["navigatiesysteem", "trekhaak", "panoramadak"],
                    "extraInfo": "Auto is in zeer goede staat en heeft altijd dealeronderhoud gehad.",
                    "naam": "Jan de Vries",
                    "email": "jan.devries@example.com",
                    "telefoon": "06-12345678",
                    "postcode": "1234 AB",
                    "status": "new",
                    "createdAt": "2023-03-12T09:30:00.000Z"
                },
                {
                    "id": "1678620481000",
                    "kenteken": "XY-789-P",
                    "merk": "BMW",
                    "model": "3-serie",
                    "bouwjaar": 2019,
                    "brandstof": "diesel",
                    "kilometerstand": 65000,
                    "transmissie": "automaat",
                    "schade": "licht",
                    "apk": "2024-08",
                    "opties": ["leer", "navigatiesysteem", "xenon"],
                    "extraInfo": "Kleine parkeerschade aan de rechterkant.",
                    "naam": "Lisa Jansen",
                    "email": "l.jansen@example.com",
                    "telefoon": "06-87654321",
                    "postcode": "5678 CD",
                    "status": "contacted",
                    "notes": "Klant heeft voorkeur om de auto binnen 2 weken te verkopen.",
                    "createdAt": "2023-03-12T12:15:00.000Z"
                },
                {
                    "id": "1678630481000",
                    "kenteken": "GH-456-R",
                    "merk": "Audi",
                    "model": "A4",
                    "bouwjaar": 2017,
                    "brandstof": "benzine",
                    "kilometerstand": 98000,
                    "transmissie": "automaat",
                    "schade": "geen",
                    "apk": "2023-12",
                    "opties": ["leer", "panoramadak"],
                    "extraInfo": "Volledig dealeronderhoud, net grote beurt gehad.",
                    "naam": "Peter Bakker",
                    "email": "peter.bakker@example.com",
                    "telefoon": "06-23456789",
                    "postcode": "3456 EF",
                    "status": "offered",
                    "notes": "Bod uitgebracht van €19.500. Klant denkt erover na.",
                    "createdAt": "2023-03-12T15:45:00.000Z"
                }
            ];
            
            await Inquiry.insertMany(sampleData);
            console.log('Added sample inquiry data');
        }
    } catch (err) {
        console.error('Error adding sample data:', err);
    }
}

// Add security middleware
app.use(helmet()); // Adds various HTTP headers for security
app.use(hpp()); // Protect against HTTP Parameter Pollution attacks
app.use(cookieParser()); // Keep cookie-parser for general cookie handling

// Add Content-Security-Policy headers to prevent XSS
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data: https:; font-src 'self' https://cdnjs.cloudflare.com data:; connect-src 'self';"
    );
    next();
});

// Add this new middleware here
app.use((req, res, next) => {
    res.setHeader('X-Robots-Tag', 'index, follow');
    next();
});

// Middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET || 'autocashsecuresecret2025',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', 
        httpOnly: true, // Prevents client-side JS from reading the cookie
        sameSite: 'strict', // Prevents CSRF attacks
        maxAge: 3600000 // 1 hour
    }
}));

// Ensure uploads directory is accessible
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

// Add to your homepage route
app.get('/', (req, res) => {
  // Just serve the static file with hardcoded meta tags
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

// Configure rate limiting for login attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 requests per window
    message: 'Te veel inlogpogingen, probeer het later opnieuw',
    standardHeaders: true,
    legacyHeaders: false,
});

app.use('/admin/login', loginLimiter);

// Authentication middleware
function isAuthenticated(req, res, next) {
    if (req.session.isAuthenticated) {
        next();
    } else {
        res.redirect('/admin/login');
    }
}

// Admin login page
app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/admin/login.html'));
});

// Admin login post handler
app.post('/admin/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    
    // Validate inputs
    if (!username || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'Gebruikersnaam en wachtwoord zijn verplicht' 
        });
    }
    
    try {
        const admin = await Admin.findOne({ username });
        
        if (!admin) {
            await bcrypt.compare(password, '$2b$12$invalidhashforcomparison');
            return res.status(401).json({ 
                success: false, 
                message: 'Ongeldige inloggegevens' 
            });
        }
        
        const passwordMatch = await bcrypt.compare(password, admin.password);
        
        if (passwordMatch) {
            req.session.isAuthenticated = true;
            req.session.username = admin.username;
            
            // Instead of JSON response, redirect directly
            return res.redirect('/admin/dashboard');
        } else {
            return res.status(401).json({ 
                success: false, 
                message: 'Ongeldige inloggegevens' 
            });
        }
    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({ 
            success: false, 
            message: 'Er is een fout opgetreden' 
        });
    }
});

// Admin logout
app.get('/admin/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        // Clear the session cookie
        res.clearCookie('connect.sid');
        res.redirect('/admin/login');
    });
});

// Admin dashboard
app.get('/admin/dashboard', isAuthenticated, (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    res.sendFile(path.join(__dirname, 'public/admin/dashboard.html'));
});

// Change password
app.post('/admin/change-password', isAuthenticated, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    try {
        const admin = await Admin.findOne({ username: req.session.username });
        
        if (!admin) {
            return res.status(404).json({ 
                success: false, 
                message: 'Admin niet gevonden' 
            });
        }
        
        const passwordMatch = await bcrypt.compare(currentPassword, admin.password);
        
        if (!passwordMatch) {
            return res.status(401).json({ 
                success: false, 
                message: 'Huidig wachtwoord is onjuist' 
            });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        admin.password = hashedPassword;
        await admin.save();
        
        return res.json({ 
            success: true, 
            message: 'Wachtwoord succesvol gewijzigd' 
        });
    } catch (err) {
        console.error('Change password error:', err);
        return res.status(500).json({ 
            success: false, 
            message: 'Er is een fout opgetreden' 
        });
    }
});

// API Endpoints for the admin panel
app.get('/api/inquiries', isAuthenticated, async (req, res) => {
    try {
        const inquiries = await Inquiry.find().sort({ createdAt: -1 });
        res.json(inquiries);
    } catch (err) {
        console.error('Error fetching inquiries:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Er is een fout opgetreden bij het ophalen van de aanvragen' 
        });
    }
});

app.get('/api/inquiries/:id', isAuthenticated, async (req, res) => {
    try {
        const inquiry = await Inquiry.findOne({ id: req.params.id });
        
        if (!inquiry) {
            return res.status(404).json({ 
                success: false, 
                message: 'Aanvraag niet gevonden' 
            });
        }
        
        res.json(inquiry);
    } catch (err) {
        console.error('Error fetching inquiry:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Er is een fout opgetreden bij het ophalen van de aanvraag' 
        });
    }
});

app.put('/api/inquiries/:id', isAuthenticated, async (req, res) => {
    try {
        const { status, notes } = req.body;
        const inquiry = await Inquiry.findOne({ id: req.params.id });
        
        if (!inquiry) {
            return res.status(404).json({ 
                success: false, 
                message: 'Aanvraag niet gevonden' 
            });
        }
        
        inquiry.status = status;
        inquiry.notes = notes;
        inquiry.updatedAt = new Date();
        
        await inquiry.save();
        
        res.json({ 
            success: true, 
            message: 'Aanvraag bijgewerkt', 
            inquiry: inquiry 
        });
    } catch (err) {
        console.error('Error updating inquiry:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Er is een fout opgetreden bij het bijwerken van de aanvraag' 
        });
    }
});

// Input validation and sanitization function
function sanitizeInput(input) {
    if (typeof input === 'string') {
        // Basic sanitization for strings
        return sanitizeHtml(input.trim(), {
            allowedTags: [],
            allowedAttributes: {}
        });
    } else if (Array.isArray(input)) {
        // Sanitize arrays
        return input.map(item => sanitizeInput(item));
    } else if (typeof input === 'object' && input !== null) {
        // Sanitize objects
        const sanitized = {};
        for (const key in input) {
            if (Object.prototype.hasOwnProperty.call(input, key)) {
                sanitized[key] = sanitizeInput(input[key]);
            }
        }
        return sanitized;
    }
    return input;
}

// Endpoint to handle form submission
app.post('/submit-car', upload.array('carImages', 5), async (req, res) => {
    const formData = sanitizeInput(req.body);
    
    try {
        // Validate required fields
        const requiredFields = ['kenteken', 'merk', 'model', 'bouwjaar', 'naam', 'email', 'telefoon'];
        for (const field of requiredFields) {
            if (!formData[field]) {
                return res.status(400).json({
                    success: false,
                    message: `Veld '${field}' is verplicht`
                });
            }
        }
        
        // Validate data types
        if (isNaN(parseInt(formData.bouwjaar))) {
            return res.status(400).json({
                success: false,
                message: 'Bouwjaar moet een geldig jaartal zijn'
            });
        }
        
        // Parse JSON string of options safely
        if (formData.opties && typeof formData.opties === 'string') {
            try {
                formData.opties = JSON.parse(formData.opties);
            } catch (e) {
                formData.opties = [];
            }
        }
        
        // Generate a unique ID
        const id = Date.now().toString();
        
        // Process uploaded images
        const imageFiles = req.files || [];
        const images = imageFiles.map(file => {
            return {
                filename: file.filename,
                path: '/uploads/' + file.filename,
                size: file.size
            };
        });
        
        // Create a new car inquiry with sanitized data
        const newInquiry = new Inquiry({
            id: id,
            kenteken: formData.kenteken,
            merk: formData.merk,
            model: formData.model,
            bouwjaar: parseInt(formData.bouwjaar),
            brandstof: formData.brandstof,
            kilometerstand: formData.kilometerstand ? parseInt(formData.kilometerstand) : null,
            transmissie: formData.transmissie,
            schade: formData.schade,
            apk: formData.apk,
            opties: Array.isArray(formData.opties) ? formData.opties : [],
            extraInfo: formData['extra-info'],
            naam: formData.naam,
            email: formData.email,
            telefoon: formData.telefoon,
            postcode: formData.postcode,
            images: images,
            status: 'new',
            createdAt: new Date()
        });
        
        await newInquiry.save();
        
        res.json({
            success: true,
            message: 'Aanvraag ontvangen',
            requestId: id
        });
    } catch (err) {
        console.error('Error saving car inquiry:', err);
        res.status(500).json({
            success: false,
            message: 'Er is een fout opgetreden bij het verwerken van uw aanvraag'
        });
    }
});

// Stats API for dashboard
app.get('/api/stats', isAuthenticated, async (req, res) => {
    try {
        const total = await Inquiry.countDocuments();
        const newCount = await Inquiry.countDocuments({ status: 'new' });
        const contacted = await Inquiry.countDocuments({ status: 'contacted' });
        const offered = await Inquiry.countDocuments({ status: 'offered' });
        const accepted = await Inquiry.countDocuments({ status: 'accepted' });
        const rejected = await Inquiry.countDocuments({ status: 'rejected' });
        const completed = await Inquiry.countDocuments({ status: 'completed' });
        
        // Get today's date in YYYY-MM-DD format
        const today = new Date().toISOString().split('T')[0];
        
        // Count today's inquiries
        const todayStart = new Date(today);
        const todayEnd = new Date(today);
        todayEnd.setDate(todayEnd.getDate() + 1);
        
        const todayCount = await Inquiry.countDocuments({
            createdAt: { $gte: todayStart, $lt: todayEnd }
        });
        
        const stats = {
            total,
            new: newCount,
            contacted,
            offered,
            accepted,
            rejected,
            completed,
            today: todayCount
        };
        
        res.json(stats);
    } catch (err) {
        console.error('Error getting stats:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Er is een fout opgetreden bij het ophalen van de statistieken' 
        });
    }
});

// Blog API endpoints
app.get('/api/blogs', async (req, res) => {
    try {
        const blogs = await Blog.find().sort({ createdAt: -1 });
        res.json(blogs);
    } catch (err) {
        console.error('Error fetching blogs:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Er is een fout opgetreden bij het ophalen van de blog posts' 
        });
    }
});

app.get('/api/blogs/:id', async (req, res) => {
    try {
        const blog = await Blog.findOne({ 
            $or: [
                { id: req.params.id },
                { slug: req.params.id }
            ]
        });
        
        if (!blog) {
            return res.status(404).json({ 
                success: false, 
                message: 'Blog post niet gevonden' 
            });
        }
        
        res.json(blog);
    } catch (err) {
        console.error('Error fetching blog:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Er is een fout opgetreden bij het ophalen van de blog post' 
        });
    }
});

app.get('/api/blogs/tag/:tag', async (req, res) => {
    try {
        const tag = req.params.tag.toLowerCase();
        
        // Filter blogs by tag and published status
        const filteredBlogs = await Blog.find({
            status: 'published',
            tags: { $in: [tag] }
        }).sort({ createdAt: -1 });
        
        res.json(filteredBlogs);
    } catch (err) {
        console.error('Error fetching blogs by tag:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Er is een fout opgetreden bij het ophalen van de blog posts' 
        });
    }
});

// Get all categories
app.get('/api/categories', async (req, res) => {
    try {
        const categories = await getAllCategories();
        res.json(categories);
    } catch (err) {
        console.error('Error fetching categories:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Er is een fout opgetreden bij het ophalen van de categorieën' 
        });
    }
});

// Get blogs by category
app.get('/api/blogs/category/:category', async (req, res) => {
    try {
        const category = req.params.category.toLowerCase();
        
        // Filter blogs by category and published status
        const filteredBlogs = await Blog.find({
            status: 'published',
            category: category
        }).sort({ createdAt: -1 });
        
        res.json(filteredBlogs);
    } catch (err) {
        console.error('Error fetching blogs by category:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Er is een fout opgetreden bij het ophalen van de blog posts' 
        });
    }
});
 
app.get('/blog/category/:category', async (req, res) => {
    try {
        const category = req.params.category.toLowerCase();
        
        // Filter blogs by category and published status
        const filteredBlogs = await Blog.find({
            status: 'published',
            category: category
        }).sort({ createdAt: -1 });
        
        if (filteredBlogs.length === 0) {
            return res.redirect('/blog');
        }
        
        let htmlTemplate = fs.readFileSync(path.join(__dirname, 'public/blog/index.html'), 'utf8');
        
        // Format category name for display (replace hyphens with spaces)
        const displayCategory = category.replace(/-/g, ' ');
        
        htmlTemplate = htmlTemplate.replace('<title>Blog - Mijnautoverkopen.be</title>', 
            `<title>Categorie: ${escapeHtml(displayCategory)} - Mijnautoverkopen.be Blog</title>`);
            
        htmlTemplate = htmlTemplate.replace('<meta name="description" content="" id="meta-description">', 
            `<meta name="description" content="Artikelen in de categorie ${escapeHtml(displayCategory)} - Mijnautoverkopen.be" id="meta-description">`);
            
        htmlTemplate = htmlTemplate.replace('<link rel="canonical" href="" id="canonical-link">', 
            `<link rel="canonical" href="https://mijnautoverkopen.be/blog/category/${category}" id="canonical-link">`);
        
        // Add ItemList structured data
        const structuredData = {
            "@context": "https://schema.org",
            "@type": "ItemList",
            "itemListElement": filteredBlogs.map((blog, index) => ({
                "@type": "ListItem",
                "position": index + 1,
                "url": `https://mijnautoverkopen.be/blog/${blog.slug}`,
                "name": blog.title
            }))
        };
        
        htmlTemplate = htmlTemplate.replace('</head>', 
            `<script type="application/ld+json">${JSON.stringify(structuredData)}</script></head>`);
        
        // Add markers to help client-side JavaScript
        htmlTemplate = htmlTemplate.replace('<body>', 
            `<body data-view-type="category" data-category="${escapeHtml(category)}">`);
            
        res.send(htmlTemplate);
    } catch (err) {
        console.error('Error rendering category page:', err);
        res.redirect('/blog');
    }
});

app.post('/api/blogs', isAuthenticated, async (req, res) => {
    try {
        const { title, excerpt, tags, status, category } = req.body;
        let { content } = req.body;
        
        // Validate required fields
        if (!title || !content) {
            return res.status(400).json({
                success: false,
                message: 'Titel en inhoud zijn verplicht'
            });
        }
        
        // Sanitize the blog content
        const sanitizedContent = sanitizeHtml(content, {
          allowedTags: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'p', 'a', 'ul', 'ol', 'li', 
                       'b', 'i', 'strong', 'em', 'strike', 'br', 'div', 'table', 'thead', 'tbody', 
                       'tr', 'th', 'td', 'pre', 'code', 'img'],
          allowedAttributes: {
            'a': ['href', 'target', 'rel'],
            'img': ['src', 'alt', 'title', 'width', 'height'],
            '*': ['class']
          },
          transformTags: {
            'a': function(tagName, attribs) {
              if (attribs.href) {
                if (attribs.href.startsWith('http')) {
                  attribs.rel = 'noopener noreferrer';
                  attribs.target = '_blank';
                }
              }
              return { tagName, attribs };
            }
          }
        });
        
        // Create a slug
        const slug = createSlug(title);
        
        // Create blog post object with sanitized content
        const newBlog = new Blog({
            id: Date.now().toString(),
            title,
            slug,
            content: sanitizedContent,
            excerpt: excerpt || sanitizedContent.substring(0, 150) + '...',
            featuredImage: req.body.featuredImage || '',
            imageAlt: req.body.imageAlt || '',
            author: req.session.username,
            status: status || 'draft',
            category: category || 'algemeen',
            tags: tags || [],
            createdAt: new Date(),
            updatedAt: new Date()
        });
        
        await newBlog.save();
        
        res.status(201).json({
            success: true,
            message: 'Blog post succesvol aangemaakt',
            blog: newBlog
        });
    } catch (err) {
        console.error('Error creating blog:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Er is een fout opgetreden bij het aanmaken van de blog post' 
        });
    }
});

app.put('/api/blogs/:id', isAuthenticated, async (req, res) => {
    try {
        const { title, excerpt, tags, status, category } = req.body;
        let { content } = req.body;
        
        const blog = await Blog.findOne({ id: req.params.id });
        
        if (!blog) {
            return res.status(404).json({ 
                success: false, 
                message: 'Blog post niet gevonden' 
            });
        }
        
        // Sanitize blog content if it's being updated
        if (content) {
            content = sanitizeHtml(content, {
              allowedTags: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'p', 'a', 'ul', 'ol', 'li', 
                           'b', 'i', 'strong', 'em', 'strike', 'br', 'div', 'table', 'thead', 'tbody', 
                           'tr', 'th', 'td', 'pre', 'code', 'img'],
              allowedAttributes: {
                'a': ['href', 'target', 'rel'],
                'img': ['src', 'alt', 'title', 'width', 'height'],
                '*': ['class']
              },
              transformTags: {
                'a': function(tagName, attribs) {
                  if (attribs.href) {
                    if (attribs.href.startsWith('http')) {
                      attribs.rel = 'noopener noreferrer';
                      attribs.target = '_blank';
                    }
                  }
                  return { tagName, attribs };
                }
              }
            });
        }
        
        // Update fields with sanitized content
        if (title) blog.title = title;
        if (content) blog.content = content;
        if (excerpt) blog.excerpt = excerpt;
        if (req.body.featuredImage) blog.featuredImage = req.body.featuredImage;
        if (req.body.imageAlt) blog.imageAlt = req.body.imageAlt;
        if (status) blog.status = status;
        if (category) blog.category = category;
        if (tags) blog.tags = tags;
        blog.updatedAt = new Date();
        
        // Update slug if title changed
        if (title && title !== blog.title) {
            blog.slug = createSlug(title);
        }
        
        await blog.save();
        
        res.json({
            success: true,
            message: 'Blog post succesvol bijgewerkt',
            blog: blog
        });
    } catch (err) {
        console.error('Error updating blog:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Er is een fout opgetreden bij het bijwerken van de blog post' 
        });
    }
});

app.delete('/api/blogs/:id', isAuthenticated, async (req, res) => {
    try {
        const blog = await Blog.findOneAndDelete({ id: req.params.id });
        
        if (!blog) {
            return res.status(404).json({ 
                success: false, 
                message: 'Blog post niet gevonden' 
            });
        }
        
        res.json({
            success: true,
            message: 'Blog post succesvol verwijderd'
        });
    } catch (err) {
        console.error('Error deleting blog:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Er is een fout opgetreden bij het verwijderen van de blog post' 
        });
    }
});

// In server.js, update the `/blog/:slug` route:
app.get('/blog/:slug', async (req, res) => {
    try {
        const blog = await Blog.findOne({ 
            slug: req.params.slug,
            status: 'published'
        });
        
        if (!blog) {
            return res.redirect('/blog');
        }
        
        // Pre-render the blog content
        let htmlTemplate = fs.readFileSync(path.join(__dirname, 'public/blog/index.html'), 'utf8');
        
        // Update metadata
        htmlTemplate = htmlTemplate.replace('<meta name="description" content="" id="meta-description">', 
            `<meta name="description" content="${escapeHtml(blog.excerpt)}" id="meta-description">`);
        
        htmlTemplate = htmlTemplate.replace('<title>Blog - Mijnautoverkopen.be</title>', 
            `<title>${escapeHtml(blog.title)} - Mijnautoverkopen.be</title>`);
            
        htmlTemplate = htmlTemplate.replace('<link rel="canonical" href="" id="canonical-link">', 
            `<link rel="canonical" href="https://mijnautoverkopen.be/blog/${blog.slug}" id="canonical-link">`);

        // Format the title for social sharing
        const socialTitle = `${blog.title} - Mijnautoverkopen.be Blog`;

        // Get excerpt or create one
        const socialDescription = blog.excerpt || blog.content.substring(0, 150).replace(/<[^>]*>/g, '') + '...';

        // Get image for sharing
        const socialImage = blog.featuredImage && blog.featuredImage.trim() !== '' 
            ? blog.featuredImage 
            : 'https://mijnautoverkopen.be/images/default-social-share.jpg';

        // Create Open Graph and Twitter Card meta tags
        let socialMetaTags = `
        <meta property="og:type" content="article" />
        <meta property="og:url" content="https://mijnautoverkopen.be/blog/${blog.slug}" />
        <meta property="og:title" content="${escapeHtml(socialTitle)}" />
        <meta property="og:description" content="${escapeHtml(socialDescription)}" />
        <meta property="og:image" content="${escapeHtml(socialImage)}" />
        <meta property="og:image:width" content="1200" />
        <meta property="og:image:height" content="630" />
        <meta property="og:locale" content="nl_NL" />
        <meta property="og:site_name" content="Mijnautoverkopen.be" />
        <meta property="article:published_time" content="${blog.createdAt}" />
        <meta property="article:modified_time" content="${blog.updatedAt || blog.createdAt}" />
        ${blog.category ? `<meta property="article:section" content="${escapeHtml(blog.category)}" />` : ''}
        ${Array.isArray(blog.tags) && blog.tags.length > 0 ? blog.tags.map(tag => `<meta property="article:tag" content="${escapeHtml(tag)}" />`).join('\n') : ''}

        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:url" content="https://mijnautoverkopen.be/blog/${blog.slug}" />
        <meta name="twitter:title" content="${escapeHtml(socialTitle)}" />
        <meta name="twitter:description" content="${escapeHtml(socialDescription)}" />
        <meta name="twitter:image" content="${escapeHtml(socialImage)}" />
        `;

        // Inject the social meta tags into the HTML
        htmlTemplate = htmlTemplate.replace('</head>', socialMetaTags + '</head>');
        
        // Create blog post structured data
        const structuredData = {
            "@context": "https://schema.org",
            "@type": "BlogPosting",
            "headline": blog.title,
            "image": blog.featuredImage,
            "description": blog.excerpt,
            "datePublished": blog.createdAt,
            "dateModified": blog.updatedAt || blog.createdAt,
            "author": { "@type": "Person", "name": blog.author || "Mijnautoverkopen Team" },
            "publisher": {
                "@type": "Organization",
                "name": "Mijnautoverkopen.be",
                "logo": {
                    "@type": "ImageObject",
                    "url": "https://mijnautoverkopen.be/logo.png"
                }
            }
        };
        
        // Replace existing structured data instead of adding new one
        const structuredDataRegex = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/;
        htmlTemplate = htmlTemplate.replace(
            structuredDataRegex, 
            `<script type="application/ld+json">${JSON.stringify(structuredData)}</script>`
        );
        
        // FORMAT THE DATE FOR DISPLAY
        const createdDate = new Date(blog.createdAt);
        const formattedDate = createdDate.toLocaleDateString('nl-NL', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
        
        // CREATE THE BLOG HTML CONTENT
        const blogContentHtml = `
    <div class="blog-header">
        <h1>${escapeHtml(blog.title)}</h1>
        ${blog.category ? `<div class="blog-category"><a href="/blog/category/${blog.category}" class="category-badge">${blog.category.replace('-', ' ')}</a></div>` : ''}
        <div class="blog-meta">
            <span><i class="far fa-calendar"></i> ${formattedDate}</span>
            <span><i class="far fa-user"></i> ${blog.author || 'Mijnautoverkopen'}</span>
        </div>
        ${Array.isArray(blog.tags) && blog.tags.length > 0 ? `
            <div class="blog-tags">
                ${blog.tags.map(tag => `<span class="blog-tag"><a href="/blog/tag/${tag}">${tag}</a></span>`).join('')}
            </div>
        ` : ''}
    </div>
    ${blog.featuredImage ? `
        <div class="blog-featured-image">
            <img src="${blog.featuredImage}" alt="${blog.imageAlt || blog.title}" class="featured-image">
        </div>
    ` : ''}
    <div class="blog-content">
        ${blog.content}
    </div>
    
    <!-- Add the social sharing buttons here -->
    <div class="social-sharing">
        <h4>Deel dit artikel</h4>
        <div class="share-buttons">
            <a href="https://www.facebook.com/sharer/sharer.php?u=https://mijnautoverkopen.be/blog/${blog.slug}" target="_blank" rel="noopener noreferrer" class="share-button facebook">
                <i class="fab fa-facebook-f"></i>
                <span>Facebook</span>
            </a>
            <a href="https://twitter.com/intent/tweet?url=https://mijnautoverkopen.be/blog/${blog.slug}&text=${encodeURIComponent(blog.title)}" target="_blank" rel="noopener noreferrer" class="share-button twitter">
                <i class="fab fa-x-twitter"></i>
                <span>X (Twitter)</span>
            </a>
            <a href="https://www.linkedin.com/shareArticle?mini=true&url=https://mijnautoverkopen.be/blog/${blog.slug}&title=${encodeURIComponent(blog.title)}&summary=${encodeURIComponent(blog.excerpt || '')}" target="_blank" rel="noopener noreferrer" class="share-button linkedin">
                <i class="fab fa-linkedin-in"></i>
                <span>LinkedIn</span>
            </a>
            <a href="mailto:?subject=${encodeURIComponent(blog.title)}&body=${encodeURIComponent('Bekijk dit artikel op Mijnautoverkopen.be: https://mijnautoverkopen.be/blog/' + blog.slug)}" class="share-button email">
                <i class="fas fa-envelope"></i>
                <span>Email</span>
            </a>
            <a href="https://api.whatsapp.com/send?text=${encodeURIComponent(blog.title + ' - https://mijnautoverkopen.be/blog/' + blog.slug)}" target="_blank" rel="noopener noreferrer" class="share-button whatsapp">
                <i class="fab fa-whatsapp"></i>
                <span>WhatsApp</span>
            </a>
        </div>
    </div>
`;
        
        // Inject the blog content into the template
        htmlTemplate = htmlTemplate.replace('<article id="blog-post-content" class="blog-single">', 
            `<article id="blog-post-content" class="blog-single" data-prerendered="true" data-blog-id="${blog.id}">${blogContentHtml}`);
        
        // Mark the page as a blog post view
        htmlTemplate = htmlTemplate.replace('<body>', 
            `<body data-view-type="post" data-slug="${blog.slug}">`);
        
        res.send(htmlTemplate);
    } catch (err) {
        console.error('Error rendering blog:', err);
        res.redirect('/blog');
    }
});

// Public endpoint to get published blogs for the frontend
app.get('/blog', (req, res) => {
  // Just serve the static file with hardcoded meta tags
  res.sendFile(path.join(__dirname, 'public/blog/index.html'));
});

app.get('/blog/tag/:tag', async (req, res) => {
    try {
        const tag = req.params.tag.toLowerCase();
        
        // Filter by tag and published status
        const filteredBlogs = await Blog.find({
            status: 'published',
            tags: { $in: [tag] }
        }).sort({ createdAt: -1 });
        
        if (filteredBlogs.length === 0) {
            return res.redirect('/blog');
        }
        
        let htmlTemplate = fs.readFileSync(path.join(__dirname, 'public/blog/index.html'), 'utf8');
        
        htmlTemplate = htmlTemplate.replace('<title>Blog - Mijnautoverkopen.be</title>', 
            `<title>Tag: ${escapeHtml(tag)} - Mijnautoverkopen.be Blog</title>`);
            
        htmlTemplate = htmlTemplate.replace('<meta name="description" content="" id="meta-description">', 
            `<meta name="description" content="Artikelen met de tag ${escapeHtml(tag)} - Mijnautoverkopen.be" id="meta-description">`);
            
        htmlTemplate = htmlTemplate.replace('<link rel="canonical" href="" id="canonical-link">', 
            `<link rel="canonical" href="https://mijnautoverkopen.be/blog/tag/${tag}" id="canonical-link">`);
        
        // Add ItemList structured data
        const structuredData = {
            "@context": "https://schema.org",
            "@type": "ItemList",
            "itemListElement": filteredBlogs.map((blog, index) => ({
                "@type": "ListItem",
                "position": index + 1,
                "url": `https://mijnautoverkopen.be/blog/${blog.slug}`,
                "name": blog.title
            }))
        };
        
        htmlTemplate = htmlTemplate.replace('</head>', 
            `<script type="application/ld+json">${JSON.stringify(structuredData)}</script></head>`);
        
        // Add markers to help client-side JavaScript
        htmlTemplate = htmlTemplate.replace('<body>', 
            `<body data-view-type="tag" data-tag="${escapeHtml(tag)}">`);
            
        res.send(htmlTemplate);
    } catch (err) {
        console.error('Error rendering tag page:', err);
        res.redirect('/blog');
    }
});

// Add after your other routes
app.get('/sitemap.xml', async (req, res) => {
    try {
        const blogs = await Blog.find({ status: 'published' });
        
        // Create XML sitemap
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
        xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
        
        // Add homepage
        xml += '  <url>\n';
        xml += '    <loc>https://mijnautoverkopen.be/</loc>\n';
        xml += '    <changefreq>weekly</changefreq>\n';
        xml += '    <priority>1.0</priority>\n';
        xml += '  </url>\n';
        
        // Add blog index
        xml += '  <url>\n';
        xml += '    <loc>https://mijnautoverkopen.be/blog</loc>\n';
        xml += '    <changefreq>daily</changefreq>\n';
        xml += '    <priority>0.8</priority>\n';
        xml += '  </url>\n';
        
        // Add all blog posts
        blogs.forEach(blog => {
            xml += '  <url>\n';
            xml += `    <loc>https://mijnautoverkopen.be/blog/${blog.slug}</loc>\n`;
            xml += `    <lastmod>${new Date(blog.updatedAt || blog.createdAt).toISOString().split('T')[0]}</lastmod>\n`;
            xml += '    <changefreq>monthly</changefreq>\n';
            xml += '    <priority>0.7</priority>\n';
            xml += '  </url>\n';
        });
        
        xml += '</urlset>';
        
        res.header('Content-Type', 'application/xml');
        res.send(xml);
    } catch (err) {
        console.error('Error generating sitemap:', err);
        res.status(500).send('Error generating sitemap');
    }
});

app.get('/robots.txt', (req, res) => {
    const robotsTxt = `User-agent: *
Allow: /
Sitemap: https://mijnautoverkopen.be/sitemap.xml`;
    
    res.type('text/plain');
    res.send(robotsTxt);
});

// Improved error handling without exposing sensitive details
function errorHandler(err, req, res, next) {
    console.error(err.stack);
    res.status(500).json({
        success: false,
        message: 'Er is een fout opgetreden'
    });
}

app.use(errorHandler);

// Start the server
app.listen(port, async () => {
    console.log(`Server running at http://localhost:${port}`);
    await initializeAdmin();
    await addSampleData();
    await addSampleBlogs();
    await migrateBlogsToAddCategories();
});