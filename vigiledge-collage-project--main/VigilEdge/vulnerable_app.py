"""
Vulnerable Web Application - Testing Target for VigilEdge WAF
This application contains intentional vulnerabilities for testing purposes
only. DO NOT USE IN PRODUCTION - FOR EDUCATIONAL/TESTING PURPOSES ONLY
"""

from fastapi import FastAPI, Request, Form, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import sqlite3
import os
from typing import Optional

# Create vulnerable app
vulnerable_app = FastAPI(
    title="VulnShop - Vulnerable E-commerce Site",
    description="Intentionally vulnerable application for WAF testing",
    version="1.0.0"
)

# Setup templates and static files
templates = Jinja2Templates(directory="templates")

# Initialize vulnerable database


def init_vulnerable_db():
    """Initialize database with vulnerable schema"""
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # Drop existing tables to ensure clean schema
    cursor.execute('DROP TABLE IF EXISTS products')
    cursor.execute('DROP TABLE IF EXISTS users')
    
    # Create vulnerable users table
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    # Create enhanced products table with more fields
    cursor.execute('''
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT,
            category TEXT,
            subcategory TEXT,
            brand TEXT,
            stock INTEGER,
            rating REAL,
            features TEXT
        )
    ''')
    
    # Insert sample vulnerable data
    cursor.execute(
        "INSERT OR REPLACE INTO users VALUES "
        "(1, 'admin', 'admin123', 'admin@vulnshop.com', 1)"
    )
    cursor.execute(
        "INSERT OR REPLACE INTO users VALUES "
        "(2, 'user', 'password', 'user@vulnshop.com', 0)"
    )
    cursor.execute(
        "INSERT OR REPLACE INTO users VALUES "
        "(3, 'guest', 'guest', 'guest@vulnshop.com', 0)"
    )
    
    # Insert comprehensive product catalog (20 products)
    products_data = [
        (1, 'Gaming Laptop Pro X1', 1899.99, 'Ultimate gaming laptop with RTX 4080, 32GB RAM, 1TB SSD', 'Electronics', 'Laptops', 'TechMaster', 15, 4.8, 'RTX 4080 GPU, 32GB DDR5 RAM, 1TB NVMe SSD, 17.3 inch 4K Display'),
        (2, 'Smartphone Pro Max 256GB', 1199.99, 'Latest flagship smartphone with triple camera system and 5G', 'Electronics', 'Smartphones', 'PhoneTech', 42, 4.6, 'Triple Camera, 5G Ready, 256GB Storage, Fast Charging'),
        (3, 'Wireless Noise-Canceling Headphones', 299.99, 'Premium wireless headphones with active noise cancellation', 'Audio', 'Headphones', 'AudioElite', 67, 4.7, 'Active Noise Cancellation, 30hr Battery, Bluetooth 5.0, Quick Charge'),
        (4, '4K Smart TV 65 inch', 799.99, 'Ultra HD 4K Smart TV with HDR support and streaming apps', 'Electronics', 'Televisions', 'ViewMaster', 23, 4.5, '4K Ultra HD, HDR Support, Smart TV Platform, Voice Control'),
        (5, 'Professional DSLR Camera Kit', 1299.99, 'Professional DSLR camera with 24MP sensor and 4K video', 'Electronics', 'Cameras', 'PhotoPro', 18, 4.9, '24MP Sensor, 4K Video, Lens Kit Included, Weather Sealed'),
        (6, 'Smart Fitness Watch', 249.99, 'Advanced fitness tracking smartwatch with GPS and heart rate monitor', 'Wearables', 'Smartwatches', 'FitTracker', 89, 4.4, 'GPS Tracking, Heart Rate Monitor, 7-day Battery, Water Resistant'),
        (7, 'Mechanical Gaming Keyboard RGB', 159.99, 'Mechanical gaming keyboard with RGB backlighting and Cherry MX switches', 'Accessories', 'Keyboards', 'GameGear', 156, 4.6, 'Cherry MX Switches, RGB Backlighting, Programmable Keys, Aluminum Frame'),
        (8, 'Wireless Gaming Mouse', 89.99, 'High-precision wireless gaming mouse with 16000 DPI sensor', 'Accessories', 'Mice', 'GameGear', 234, 4.5, '16000 DPI Sensor, Wireless, Customizable Buttons, RGB Lighting'),
        (9, 'Bluetooth Portable Speaker', 79.99, 'Waterproof portable Bluetooth speaker with 360-degree sound', 'Audio', 'Speakers', 'SoundWave', 78, 4.3, '360° Sound, Waterproof, 12hr Battery, Voice Assistant'),
        (10, 'USB-C Hub Multi-Port Adapter', 49.99, '7-in-1 USB-C hub with HDMI, USB 3.0, and SD card reader', 'Accessories', 'Adapters', 'ConnectPro', 189, 4.2, '7-in-1 Design, HDMI 4K Output, Fast Charging, Compact Design'),
        (11, 'Wireless Charging Pad Pro', 39.99, 'Fast wireless charging pad with LED indicators and phone stand', 'Accessories', 'Chargers', 'ChargeTech', 145, 4.3, '15W Fast Charging, LED Status, Phone Stand, Case Friendly'),
        (12, 'Gaming Chair Ergonomic Pro', 299.99, 'Professional gaming chair with lumbar support and RGB lighting', 'Furniture', 'Gaming Chairs', 'ComfortGame', 34, 4.7, 'Lumbar Support, RGB Lighting, Adjustable Height, Memory Foam'),
        (13, 'Webcam 4K Ultra HD', 149.99, '4K webcam with auto-focus and noise-canceling microphone', 'Electronics', 'Webcams', 'StreamMaster', 78, 4.5, '4K Recording, Auto Focus, Noise Canceling Mic, USB Plug & Play'),
        (14, 'Portable SSD 1TB', 179.99, 'Ultra-fast portable SSD with USB-C connectivity', 'Storage', 'External Drives', 'SpeedStore', 167, 4.8, '1TB Capacity, USB-C 3.2, 540MB/s Speed, Shock Resistant'),
        (15, 'VR Headset Elite', 599.99, 'Advanced VR headset with 4K display and spatial tracking', 'Electronics', 'VR Headsets', 'VirtualTech', 28, 4.6, '4K Per Eye, 120Hz Refresh, Spatial Tracking, Wireless'),
        (16, 'Electric Standing Desk', 449.99, 'Height-adjustable electric standing desk with memory presets', 'Furniture', 'Desks', 'ErgoWork', 19, 4.4, 'Electric Height Adjust, Memory Presets, Cable Management, 48x30 inch'),
        (17, 'Drone 4K Camera Pro', 899.99, 'Professional drone with 4K camera and GPS auto-return', 'Electronics', 'Drones', 'SkyMaster', 41, 4.7, '4K Camera, GPS Auto Return, 30min Flight Time, Obstacle Avoidance'),
        (18, 'Smart Home Hub', 129.99, 'Central smart home hub with voice control and app integration', 'Smart Home', 'Hubs', 'SmartLife', 93, 4.2, 'Voice Control, Multi-Protocol, App Integration, Local Processing'),
        (19, 'Mechanical Keyboard Full Size', 189.99, 'Full-size mechanical keyboard with hot-swappable switches', 'Accessories', 'Keyboards', 'TypeMaster', 112, 4.9, 'Hot-Swappable, RGB Per Key, Aluminum Frame, USB-C Detachable'),
        (20, 'Smart Security Camera', 89.99, 'WiFi security camera with night vision and motion detection', 'Smart Home', 'Security', 'SecureWatch', 156, 4.1, '1080p HD, Night Vision, Motion Detection, Cloud Storage')
    ]
    
    # Insert all products
    for product in products_data:
        cursor.execute(
            "INSERT OR REPLACE INTO products VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", product
        )
    
    conn.commit()
    conn.close()


# Initialize database on startup
init_vulnerable_db()


@vulnerable_app.get("/", response_class=HTMLResponse)
async def vulnerable_home(request: Request):
    """Enhanced homepage with role-based navigation"""
    # Get search query from URL parameters (vulnerable to XSS)
    search = request.query_params.get("search", "")
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnShop - Online Store</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                min-height: 100vh;
            }}
            .header {{
                background: linear-gradient(135deg, #007bff, #0056b3);
                color: white;
                padding: 40px;
                text-align: center;
            }}
            .hero {{
                background: #f8f9fa;
                padding: 50px;
                text-align: center;
            }}
            .auth-section {{
                display: grid;
                grid-template-columns: 1fr 1fr 1fr;
                gap: 30px;
                padding: 40px;
                background: #e9ecef;
            }}
            .auth-card {{
                background: white;
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                text-align: center;
            }}
            .auth-card h3 {{
                margin-top: 0;
            }}
            .btn {{
                display: inline-block;
                padding: 12px 25px;
                text-decoration: none;
                border-radius: 8px;
                font-weight: bold;
                margin: 10px;
                transition: all 0.3s;
            }}
            .btn-primary {{
                background: #007bff;
                color: white;
            }}
            .btn-success {{
                background: #28a745;
                color: white;
            }}
            .btn-danger {{
                background: #dc3545;
                color: white;
            }}
            .btn:hover {{
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            }}
            .nav {{
                display: flex;
                justify-content: center;
                gap: 30px;
                padding: 20px;
                background: #343a40;
            }}
            .nav a {{
                color: white;
                text-decoration: none;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 5px;
            }}
            .nav a:hover {{
                background: #495057;
            }}
            .search-box {{
                text-align: center;
                margin: 30px 0;
            }}
            .search-box input {{
                padding: 12px;
                width: 400px;
                border: 1px solid #ddd;
                border-radius: 25px;
            }}
            .search-box button {{
                padding: 12px 25px;
                background: #007bff;
                color: white;
                border: none;
                border-radius: 25px;
                cursor: pointer;
                margin-left: 10px;
            }}
            .features {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 30px;
                padding: 50px;
            }}
            .feature {{
                background: #f8f9fa;
                padding: 30px;
                border-radius: 10px;
                text-align: center;
            }}
            .feature h4 {{
                color: #007bff;
            }}
            .warning {{
                background: #fff3cd;
                color: #856404;
                padding: 20px;
                border-radius: 10px;
                margin: 30px;
                border: 1px solid #ffeaa7;
            }}
            .footer {{
                background: #343a40;
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .demo-accounts {{
                background: #d1ecf1;
                padding: 20px;
                border-radius: 10px;
                margin: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛒 VulnShop</h1>
                <p>Your One-Stop Vulnerable Shopping Experience</p>
                <p style="font-size: 18px; margin-top: 20px;">🎯 Educational Platform for Security Testing</p>
            </div>
            
            <div class="warning">
                ⚠️ <strong>IMPORTANT:</strong> This is a deliberately vulnerable application created for WAF testing and security education purposes only. Do not use in production environments!
            </div>
            
            <div class="auth-section">
                <div class="auth-card">
                    <h3>👤 Customer Portal</h3>
                    <p>Shop products, manage orders, and track your purchases with our customer account system.</p>
                    <a href="/user/login" class="btn btn-success">Customer Login</a>
                    <a href="/register" class="btn btn-primary">Create Account</a>
                    <div class="demo-accounts">
                        <strong>Demo Account:</strong><br>
                        Username: user<br>
                        Password: password
                    </div>
                </div>
                
                <div class="auth-card">
                    <h3>🔐 Admin Panel</h3>
                    <p>Administrative access for managing users, viewing logs, and configuring system settings.</p>
                    <a href="/admin/login" class="btn btn-danger">Admin Login</a>
                    <div class="demo-accounts">
                        <strong>Admin Token:</strong><br>
                        admin123
                    </div>
                </div>
                
                <div class="auth-card">
                    <h3>🛍️ Browse Catalog</h3>
                    <p>Explore our product catalog and test various e-commerce functionalities without registration.</p>
                    <a href="/products" class="btn btn-primary">View Products</a>
                    <a href="/contact" class="btn btn-primary">Contact Us</a>
                </div>
            </div>
            
            <div class="nav">
                <a href="/">🏠 Home</a>
                <a href="/products">🛍️ Products</a>
                <a href="/upload">📁 File Upload</a>
                <a href="/contact">📧 Contact</a>
                <a href="/login">🔑 Secure Login</a>
            </div>
            
            <div class="search-box">
                <form method="GET">
                    <input type="text" name="search" placeholder="Search for products (XSS vulnerable)..." value="{search}">
                    <button type="submit">🔍 Search</button>
                </form>
                <div style="margin: 15px 0; color: #666; font-style: italic;">
                    Search Result: {search}
                </div>
            </div>
            
            <div class="features">
                <div class="feature">
                    <h4>🛡️ Secure Database Queries</h4>
                    <p>Database queries now use parameterized statements to prevent SQL injection attacks.</p>
                    <a href="/login" class="btn btn-primary">Test Login</a>
                </div>
                
                <div class="feature">
                    <h4>💉 XSS Vulnerabilities</h4>
                    <p>Practice cross-site scripting attacks through search forms and contact submissions.</p>
                    <a href="/contact" class="btn btn-primary">Test XSS</a>
                </div>
                
                <div class="feature">
                    <h4>📁 File Upload Exploits</h4>
                    <p>Explore file upload vulnerabilities and test malicious file detection systems.</p>
                    <a href="/upload" class="btn btn-primary">Upload Files</a>
                </div>
                
                <div class="feature">
                    <h4>🔐 Authentication Bypass</h4>
                    <p>Test authentication mechanisms and privilege escalation vulnerabilities.</p>
                    <a href="/admin" class="btn btn-primary">Admin Panel</a>
                </div>
                
                <div class="feature">
                    <h4>👥 User Management</h4>
                    <p>Customer registration, profile management, and role-based access control testing.</p>
                    <a href="/register" class="btn btn-primary">Register</a>
                </div>
                
                <div class="feature">
                    <h4>📊 Security Monitoring</h4>
                    <p>View attack logs, system monitoring, and security configuration panels.</p>
                    <a href="/admin?token=admin123" class="btn btn-primary">View Logs</a>
                </div>
            </div>
            
            <div style="background: #f8f9fa; padding: 40px; text-align: center;">
                <h3>🎯 Testing Endpoints</h3>
                <p>Use these endpoints to test your WAF protection:</p>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; max-width: 800px; margin: 0 auto; text-align: left;">
                    <div>
                        <strong>SQL Injection:</strong><br>
                        <code>/products?id=1' OR 1=1--</code><br>
                        <code>/login (try: admin' OR '1'='1' --)</code>
                    </div>
                    <div>
                        <strong>XSS Attacks:</strong><br>
                        <code>/?search=&lt;script&gt;alert('XSS')&lt;/script&gt;</code><br>
                        <code>/contact (in form fields)</code>
                    </div>
                    <div>
                        <strong>File Upload:</strong><br>
                        <code>/upload (try malicious files)</code><br>
                        <code>/file?path=../../../etc/passwd</code>
                    </div>
                    <div>
                        <strong>Authentication:</strong><br>
                        <code>/admin?token=admin123</code><br>
                        <code>/admin/users (direct access)</code>
                    </div>
                </div>
            </div>
            
            <div class="footer">
                <p>&copy; 2024 VulnShop - Educational Security Testing Platform</p>
                <p>Created for WAF testing and cybersecurity education</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)

@vulnerable_app.get("/login", response_class=HTMLResponse)
async def login_form():
    """Vulnerable login form"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            .form-group { margin: 15px 0; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
            button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
            .warning { background: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .attack-examples { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔐 Login to VulnShop</h2>
            <div class="warning">
                ⚠️ This login form is vulnerable to SQL injection attacks!
            </div>
            
            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">Login</button>
            </form>
            
            <div style="text-align: center; margin: 15px 0;">
                <a href="/forgot-password" style="color: #007bff; text-decoration: none;">
                    🔑 Forgot your password?
                </a>
            </div>
            
            <div class="attack-examples">
                <h4>🎯 SQL Injection Attack Examples:</h4>
                <ul>
                    <li><code>admin' OR '1'='1' --</code></li>
                    <li><code>' UNION SELECT * FROM users --</code></li>
                    <li><code>admin'; DROP TABLE users; --</code></li>
                </ul>
            </div>
            
            <p><a href="/">← Back to Home</a></p>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.post("/login")
async def vulnerable_login(username: str = Form(...), password: str = Form(...)):
    """Vulnerable login endpoint with SQL injection"""
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        print(f"Executing query: {query} with parameters: {username}, [password hidden]")  # For demonstration
        
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return JSONResponse({
                "status": "success",
                "message": f"Login successful! Welcome {user[1]}",
                "user_id": user[0],
                "is_admin": bool(user[4]),
                "executed_query": query  # Show the vulnerable query
            })
        else:
            return JSONResponse({
                "status": "error",
                "message": "Invalid credentials",
                "executed_query": query
            }, status_code=401)
            
    except Exception as e:
        return JSONResponse({
            "status": "error",
            "message": f"Database error: {str(e)}",
            "executed_query": query
        }, status_code=500)

@vulnerable_app.get("/products")
async def vulnerable_products(id: Optional[str] = None, search: Optional[str] = None, category: Optional[str] = None):
    """Enhanced vulnerable products endpoint with comprehensive catalog display"""
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # Try to convert id to integer, ignore if not a valid integer
        product_id = None
        if id:
            try:
                product_id = int(id)
            except (ValueError, TypeError):
                # Ignore non-integer IDs (like VS Code UUIDs)
                product_id = None
        
        if product_id:
            # SECURE: Parameterized query
            query = "SELECT * FROM products WHERE id = ?"
            print(f"🔍 Executing SQL query: {query} with parameter: {product_id}")
            cursor.execute(query, (product_id,))
        elif search:
            # SECURE: Parameterized query with LIKE
            query = "SELECT * FROM products WHERE name LIKE ? OR description LIKE ? OR brand LIKE ?"
            search_param = f"%{search}%"
            print(f"🔍 Executing SQL query: {query} with parameter: {search_param}")
            cursor.execute(query, (search_param, search_param, search_param))
        elif category:
            # SECURE: Parameterized query
            query = "SELECT * FROM products WHERE category = ?"
            print(f"🔍 Executing SQL query: {query} with parameter: {category}")
            cursor.execute(query, (category,))
        else:
            query = "SELECT * FROM products ORDER BY category, name"
            print(f"🔍 Executing SQL query: {query}")
            cursor.execute(query)
        products = cursor.fetchall()
        conn.close()
        
        # If no specific format requested, return HTML page
        if not id and not search and not category:
            return HTMLResponse(generate_products_catalog_html(products))
        
        return JSONResponse({
            "products": products,
            "count": len(products),
            "executed_query": query,
            "vulnerability": "SQL injection vulnerabilities have been patched with parameterized queries"
        })
        
    except Exception as e:
        return JSONResponse({
            "error": str(e),
            "executed_query": query if 'query' in locals() else "Query failed",
            "message": "SQL injection may have caused this error"
        }, status_code=500)

def generate_products_catalog_html(products):
    """Generate comprehensive HTML catalog for all products"""
    
    # Get unique categories for filter
    categories = set()
    for product in products:
        if len(product) > 4:  # Check if product has category field
            categories.add(product[4])  # category is at index 4
    
    products_html = ""
    for product in products:
        # Handle both old and new product formats
        if len(product) >= 10:  # New format with all fields
            product_id, name, price, description, category, subcategory, brand, stock, rating, features = product
        else:  # Old format for backward compatibility
            product_id, name, price, description = product[:4]
            category = subcategory = brand = features = "Unknown"
            stock = rating = 0
        
        # Parse features if it's a string
        features_list = features.split(', ') if isinstance(features, str) else []
        features_html = ""
        for feature in features_list:
            features_html += f'<span class="feature-tag">{feature}</span>'
        
        products_html += f"""
        <div class="product-card">
            <div class="product-image">
                <div class="image-placeholder">📷</div>
            </div>
            <div class="product-info">
                <h3 class="product-name">{name}</h3>
                <p class="product-brand">{brand}</p>
                <p class="product-price">${price:.2f}</p>
                <p class="product-description">{description}</p>
                <div class="product-features">
                    {features_html}
                </div>
                <div class="product-meta">
                    <span class="stock">Stock: {stock}</span>
                    <span class="rating">⭐ {rating}</span>
                    <span class="category">{category}</span>
                </div>
                <button class="add-to-cart-btn" onclick="addToCart({product_id})">Add to Cart</button>
            </div>
        </div>
        """
    
    category_options = ""
    for cat in sorted(categories):
        category_options += f'<option value="{cat}">{cat}</option>'
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnShop Products - Complete Catalog</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }}
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                background: white;
                min-height: 100vh;
            }}
            .header {{
                background: linear-gradient(135deg, #28a745, #20c997);
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .filters {{
                background: #f8f9fa;
                padding: 20px;
                border-bottom: 1px solid #dee2e6;
            }}
            .filter-row {{
                display: flex;
                gap: 15px;
                align-items: center;
                flex-wrap: wrap;
            }}
            .filter-group {{
                display: flex;
                flex-direction: column;
                gap: 5px;
            }}
            .filter-group label {{
                font-weight: bold;
                font-size: 14px;
            }}
            .filter-group select, .filter-group input {{
                padding: 8px 12px;
                border: 1px solid #ced4da;
                border-radius: 5px;
                font-size: 14px;
            }}
            .search-input {{
                flex: 1;
                min-width: 300px;
            }}
            .products-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
                gap: 25px;
                padding: 30px;
            }}
            .product-card {{
                background: white;
                border-radius: 12px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                overflow: hidden;
                transition: transform 0.3s ease, box-shadow 0.3s ease;
                border: 1px solid #e9ecef;
            }}
            .product-card:hover {{
                transform: translateY(-5px);
                box-shadow: 0 8px 25px rgba(0,0,0,0.15);
            }}
            .product-image {{
                height: 200px;
                background: linear-gradient(45deg, #f8f9fa, #e9ecef);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 48px;
                color: #6c757d;
            }}
            .product-info {{
                padding: 20px;
            }}
            .product-name {{
                font-size: 18px;
                font-weight: bold;
                color: #343a40;
                margin: 0 0 8px 0;
                line-height: 1.3;
            }}
            .product-brand {{
                font-size: 14px;
                color: #6c757d;
                margin: 0 0 10px 0;
                font-weight: 500;
            }}
            .product-price {{
                font-size: 24px;
                font-weight: bold;
                color: #28a745;
                margin: 0 0 12px 0;
            }}
            .product-description {{
                font-size: 14px;
                color: #495057;
                line-height: 1.5;
                margin: 0 0 15px 0;
            }}
            .product-features {{
                margin: 15px 0;
            }}
            .feature-tag {{
                display: inline-block;
                background: #e3f2fd;
                color: #1976d2;
                padding: 4px 8px;
                border-radius: 12px;
                font-size: 12px;
                margin: 2px;
                border: 1px solid #bbdefb;
            }}
            .product-meta {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin: 15px 0;
                font-size: 13px;
                color: #6c757d;
            }}
            .stock {{
                background: #d4edda;
                color: #155724;
                padding: 3px 8px;
                border-radius: 10px;
            }}
            .rating {{
                font-weight: bold;
            }}
            .category {{
                background: #f8d7da;
                color: #721c24;
                padding: 3px 8px;
                border-radius: 10px;
            }}
            .add-to-cart-btn {{
                width: 100%;
                background: #007bff;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
                cursor: pointer;
                transition: background-color 0.3s ease;
            }}
            .add-to-cart-btn:hover {{
                background: #0056b3;
            }}
            .stats {{
                background: #343a40;
                color: white;
                padding: 15px 30px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .nav-links {{
                text-align: center;
                padding: 20px;
                background: #f8f9fa;
                border-top: 1px solid #dee2e6;
            }}
            .nav-links a {{
                color: #007bff;
                text-decoration: none;
                margin: 0 15px;
                font-weight: bold;
            }}
            .vulnerability-info {{
                background: #fff3cd;
                color: #856404;
                padding: 15px;
                margin: 20px;
                border-radius: 8px;
                border: 1px solid #ffeaa7;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛒 VulnShop Product Catalog</h1>
                <p>Complete collection of tech products</p>
            </div>
            
            <div class="filters">
                <div class="filter-row">
                    <div class="filter-group">
                        <label>Search Products:</label>
                        <input type="text" class="search-input" placeholder="Search by name, description, or brand..." onkeyup="searchProducts(this.value)">
                    </div>
                    <div class="filter-group">
                        <label>Category:</label>
                        <select onchange="filterByCategory(this.value)">
                            <option value="">All Categories</option>
                            {category_options}
                        </select>
                    </div>
                </div>
            </div>
            
            <div class="stats">
                <span>📊 Total Products: {len(products)}</span>
                <span>🏪 Categories: {len(categories)}</span>
            </div>
            
            <div class="products-grid">
                {products_html}
            </div>
            
            <div class="nav-links">
                <a href="/">🏠 Home</a>
                <a href="/login">🔐 Login</a>
                <a href="/admin">⚙️ Admin Panel</a>
                <a href="/upload">📁 File Upload</a>
                <a href="/contact">📧 Contact</a>
            </div>
        </div>
        
        <script>
            function searchProducts(query) {{
                if (query.length > 2) {{
                    window.location.href = `/products?search=${{encodeURIComponent(query)}}`;
                }}
            }}
            
            function filterByCategory(category) {{
                if (category) {{
                    window.location.href = `/products?category=${{encodeURIComponent(category)}}`;
                }} else {{
                    window.location.href = '/products';
                }}
            }}
            
            function addToCart(productId) {{
                alert(`Product ${{productId}} added to cart! (This would be a real cart in a production app)`);
            }}
        </script>
    </body>
    </html>
    """

@vulnerable_app.get("/upload", response_class=HTMLResponse)
async def upload_form():
    """Vulnerable file upload form"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>File Upload - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            .warning { background: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .upload-area { border: 2px dashed #007bff; padding: 40px; text-align: center; border-radius: 10px; margin: 20px 0; }
            .form-group { margin: 15px 0; }
            button { padding: 12px 24px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>📁 File Upload</h2>
            <div class="warning">
                ⚠️ This upload endpoint accepts any file type without validation!
            </div>
            
            <form method="POST" action="/upload" enctype="multipart/form-data">
                <div class="upload-area">
                    <input type="file" name="file" required>
                    <p>Select any file to upload (no restrictions!)</p>
                </div>
                <button type="submit">Upload File</button>
            </form>
            
            <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
                <h4>🎯 Attack Examples:</h4>
                <ul>
                    <li>Upload PHP shell: <code>shell.php</code></li>
                    <li>Upload malicious script: <code>malware.js</code></li>
                    <li>Upload executable: <code>virus.exe</code></li>
                    <li>Upload with double extension: <code>image.jpg.php</code></li>
                </ul>
            </div>
            
            <p><a href="/">← Back to Home</a></p>
        </div>
    </body>
    </html>
    """

@vulnerable_app.post("/upload")
async def vulnerable_upload(file: UploadFile = File(...)):
    """Vulnerable file upload endpoint"""
    try:
        # VULNERABLE: No file type validation, no size limits
        upload_dir = "uploads"
        os.makedirs(upload_dir, exist_ok=True)
        
        file_path = os.path.join(upload_dir, file.filename)
        
        # Save file without any validation
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        return JSONResponse({
            "status": "success",
            "message": f"File '{file.filename}' uploaded successfully!",
            "file_path": file_path,
            "file_size": len(content),
            "vulnerability": "No file type validation or size limits applied"
        })
        
    except Exception as e:
        return JSONResponse({
            "status": "error",
            "message": str(e)
        }, status_code=500)

@vulnerable_app.get("/file")
async def vulnerable_file_read(path: str):
    """Vulnerable file reading endpoint (Directory Traversal)"""
    try:
        # VULNERABLE: Direct file path access
        full_path = os.path.join("uploads", path)
        
        # Try to read the file
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        
        return JSONResponse({
            "file_path": full_path,
            "content": content[:1000],  # Limit output
            "vulnerability": "Directory traversal possible - try '../../../etc/passwd'"
        })
        
    except Exception as e:
        return JSONResponse({
            "error": str(e),
            "attempted_path": path,
            "vulnerability": "Directory traversal attack detected"
        }, status_code=500)


@vulnerable_app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_form():
    """Admin login form"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Login - VulnShop</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            .login-container {
                background: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
                width: 100%;
                max-width: 400px;
                position: relative;
            }
            
            .login-header {
                text-align: center;
                margin-bottom: 30px;
            }
            
            .login-header h1 {
                color: #333;
                font-size: 28px;
                margin-bottom: 8px;
                font-weight: 600;
            }
            
            .login-header p {
                color: #666;
                font-size: 14px;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            .form-group label {
                display: block;
                margin-bottom: 8px;
                color: #333;
                font-weight: 500;
                font-size: 14px;
            }
            
            .form-group input {
                width: 100%;
                padding: 12px 16px;
                border: 2px solid #e1e5e9;
                border-radius: 8px;
                font-size: 16px;
                transition: border-color 0.3s ease;
                background: #f8f9fa;
            }
            
            .form-group input:focus {
                outline: none;
                border-color: #667eea;
                background: white;
            }
            
            .login-btn {
                width: 100%;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 14px;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s ease;
            }
            
            .login-btn:hover {
                transform: translateY(-2px);
            }
            
            .login-btn:active {
                transform: translateY(0);
            }
            
            .security-notice {
                background: #fff3cd;
                border: 1px solid #ffeaa7;
                color: #856404;
                padding: 12px;
                border-radius: 8px;
                margin-bottom: 20px;
                font-size: 14px;
                text-align: center;
            }
            
            .demo-credentials {
                background: #d1ecf1;
                border: 1px solid #bee5eb;
                color: #0c5460;
                padding: 15px;
                border-radius: 8px;
                margin-top: 20px;
                font-size: 13px;
            }
            
            .demo-credentials h4 {
                margin-bottom: 8px;
                font-size: 14px;
            }
            
            .demo-credentials code {
                background: rgba(0,0,0,0.1);
                padding: 2px 6px;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
            }
            
            .back-link {
                text-align: center;
                margin-top: 20px;
            }
            
            .back-link a {
                color: #667eea;
                text-decoration: none;
                font-size: 14px;
            }
            
            .back-link a:hover {
                text-decoration: underline;
            }
            
            .admin-icon {
                width: 60px;
                height: 60px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 20px;
                color: white;
                font-size: 24px;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <div class="admin-icon">🔐</div>
                <h1>Admin Login</h1>
                <p>VulnShop Administrative Access</p>
            </div>
            
            <div class="security-notice">
                ⚠️ <strong>Demo Environment:</strong> For educational purposes only
            </div>
            
            <form action="/admin/login" method="POST">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" placeholder="Enter admin username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" placeholder="Enter admin password" required>
                </div>
                
                <button type="submit" class="login-btn">
                    🚀 Login to Admin Panel
                </button>
            </form>
            
            <div class="forgot-password-link" style="text-align: center; margin: 15px 0;">
                <a href="/forgot-password" style="color: #667eea; text-decoration: none; font-size: 14px;">
                    🔑 Forgot your password?
                </a>
            </div>
            
            <div class="demo-credentials">
                <h4>📋 Demo Credentials:</h4>
                <p><strong>Username:</strong> <code>admin</code></p>
                <p><strong>Password:</strong> <code>admin123</code></p>
                <p style="margin-top: 8px; font-style: italic;">These are intentionally weak credentials for testing purposes.</p>
            </div>
            
            <div class="back-link">
                <a href="/">← Back to VulnShop Home</a>
            </div>
        </div>
        
        <script>
            // Auto-focus on username field
            document.getElementById('username').focus();
            
            // Handle form submission
            document.querySelector('form').addEventListener('submit', function(e) {
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                if (!username || !password) {
                    e.preventDefault();
                    alert('Please enter both username and password');
                    return;
                }
            });
        </script>
    </body>
    </html>
    """)


@vulnerable_app.post("/admin/login")
async def admin_login_submit(username: str = Form(...), password: str = Form(...)):
    """Handle admin login submission"""
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # Check admin credentials
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ? AND is_admin = 1", (username, password))
        admin_user = cursor.fetchone()
        conn.close()
        
        if admin_user:
            # Successful login - redirect to admin panel
            response = RedirectResponse(url="/admin?token=admin123", status_code=302)
            response.set_cookie(key="admin_session", value="admin123", max_age=3600)
            return response
        else:
            # Failed login
            return HTMLResponse("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login Failed - VulnShop Admin</title>
                <style>
                    body { font-family: Arial, sans-serif; background: #f8f9fa; padding: 40px; }
                    .error-container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .error-header { color: #dc3545; text-align: center; margin-bottom: 20px; }
                    .error-message { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                    .btn { display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }
                    .btn:hover { background: #0056b3; }
                </style>
            </head>
            <body>
                <div class="error-container">
                    <div class="error-header">
                        <h2>🚫 Login Failed</h2>
                    </div>
                    <div class="error-message">
                        <strong>Access Denied:</strong> Invalid username or password. Please check your credentials and try again.
                    </div>
                    <p><strong>Security Note:</strong> This login attempt has been logged for security purposes.</p>
                    <a href="/admin/login" class="btn">← Try Again</a>
                    <a href="/" class="btn" style="background: #6c757d; margin-left: 10px;">Back to Home</a>
                </div>
            </body>
            </html>
            """, status_code=401)
            
    except Exception as e:
        return JSONResponse({
            "error": "Login system error",
            "message": str(e)
        }, status_code=500)


@vulnerable_app.get("/admin")
async def vulnerable_admin(token: Optional[str] = None):
    """Vulnerable admin panel"""
    # VULNERABLE: Weak authentication
    if token != "admin123":
        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
        <head><title>Admin Access Required</title></head>
        <body style="font-family: Arial; margin: 40px;">
            <h2>🔒 Admin Access Required</h2>
            <p>Please provide admin token:</p>
            <form method="GET">
                <input type="text" name="token" placeholder="Enter admin token">
                <button type="submit">Access</button>
            </form>
            <p><strong>Hint:</strong> Try common passwords like 'admin123', 'password', '123456'</p>
            <p><a href="/">← Back to Home</a></p>
        </body>
        </html>
        """)
    
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel - VulnShop</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; background: #f8f9fa; }}
            .header {{ background: #dc3545; color: white; padding: 20px; text-align: center; }}
            .container {{ max-width: 1200px; margin: 0 auto; padding: 30px; }}
            .dashboard-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 30px 0; }}
            .card {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .card h3 {{ color: #dc3545; margin-top: 0; }}
            .btn {{ display: inline-block; padding: 10px 20px; background: #dc3545; color: white; text-decoration: none; border-radius: 5px; margin: 5px; }}
            .btn:hover {{ background: #c82333; }}
            .stats {{ display: flex; justify-content: space-around; background: #d4edda; padding: 20px; border-radius: 10px; margin: 20px 0; }}
            .stat {{ text-align: center; }}
            .stat-number {{ font-size: 2em; font-weight: bold; color: #155724; }}
            .nav {{ background: #343a40; padding: 15px; }}
            .nav a {{ color: white; text-decoration: none; margin: 0 15px; }}
            .nav a:hover {{ color: #ffc107; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔐 VulnShop Admin Dashboard</h1>
            <p>Administrative Control Panel - Access Token: admin123</p>
        </div>
        
        <div class="nav">
            <a href="/admin?token=admin123">Dashboard</a>
            <a href="/admin/users?token=admin123">User Management</a>
            <a href="/admin/logs?token=admin123">System Logs</a>
            <a href="/admin/config?token=admin123">Configuration</a>
            <a href="/">← Back to VulnShop</a>
        </div>
        
        <div class="container">
            <div class="stats">
                <div class="stat">
                    <div class="stat-number">3</div>
                    <div>Total Users</div>
                </div>
                <div class="stat">
                    <div class="stat-number">3</div>
                    <div>Products</div>
                </div>
                <div class="stat">
                    <div class="stat-number">15</div>
                    <div>Attack Attempts</div>
                </div>
                <div class="stat">
                    <div class="stat-number">Active</div>
                    <div>System Status</div>
                </div>
            </div>
            
            <div class="dashboard-grid">
                <div class="card">
                    <h3>👥 User Management</h3>
                    <p>Manage registered users, view profiles, and control access permissions.</p>
                    <a href="/admin/users?token=admin123" class="btn">Manage Users</a>
                </div>
                
                <div class="card">
                    <h3>📊 System Logs</h3>
                    <p>View application logs, security events, and attack attempts.</p>
                    <a href="/admin/logs?token=admin123" class="btn">View Logs</a>
                </div>
                
                <div class="card">
                    <h3>⚙️ Configuration</h3>
                    <p>System settings, security configurations, and application parameters.</p>
                    <a href="/admin/config?token=admin123" class="btn">Configure</a>
                </div>
                
                <div class="card">
                    <h3>🛍️ Product Management</h3>
                    <p>Add, edit, or remove products from the store catalog.</p>
                    <a href="/admin/products?token=admin123" class="btn">Manage Products</a>
                </div>
                
                <div class="card">
                    <h3>🔍 Vulnerability Testing</h3>
                    <p>Access testing endpoints and vulnerability demonstrations.</p>
                    <a href="/admin/testing?token=admin123" class="btn">Testing Tools</a>
                </div>
                
                <div class="card">
                    <h3>💾 Database</h3>
                    <p>Direct database access and SQL query interface (Vulnerable!).</p>
                    <a href="/admin/database?token=admin123" class="btn">Database Access</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.get("/admin/users")
async def admin_users(token: Optional[str] = None):
    """Admin user management page"""
    if token != "admin123":
        return HTMLResponse("<h2>Access Denied</h2><p><a href='/admin'>Go to Admin Login</a></p>")
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    
    users_html = ""
    for user in users:
        admin_badge = "👑 Admin" if user[4] else "👤 User"
        users_html += f"""
        <tr>
            <td>{user[0]}</td>
            <td>{user[1]}</td>
            <td>***hidden***</td>
            <td>{user[2]}</td>
            <td>{admin_badge}</td>
            <td><button onclick="deleteUser({user[0]})">Delete</button></td>
        </tr>
        """
    
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>User Management - Admin</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }}
            .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background: #dc3545; color: white; }}
            .btn {{ padding: 8px 15px; background: #dc3545; color: white; border: none; border-radius: 5px; cursor: pointer; }}
            .nav {{ margin-bottom: 20px; }}
            .nav a {{ color: #dc3545; text-decoration: none; margin-right: 15px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="nav">
                <a href="/admin?token=admin123">← Back to Dashboard</a>
            </div>
            <h2>👥 User Management</h2>
            <table>
                <thead>
                    <tr><th>ID</th><th>Username</th><th>Password</th><th>Email</th><th>Role</th><th>Actions</th></tr>
                </thead>
                <tbody>
                    {users_html}
                </tbody>
            </table>
        </div>
        <script>
            function deleteUser(id) {{
                if(confirm('Delete user with ID ' + id + '?')) {{
                    alert('Delete functionality not implemented (for safety)');
                }}
            }}
        </script>
    </body>
    </html>
    """)

@vulnerable_app.get("/admin/logs")
async def admin_logs(token: Optional[str] = None):
    """Admin system logs page"""
    if token != "admin123":
        return HTMLResponse("<h2>Access Denied</h2><p><a href='/admin'>Go to Admin Login</a></p>")
    
    import datetime
    logs = [
        ("2024-01-15 10:30:25", "INFO", "User login attempt: admin"),
        ("2024-01-15 10:31:15", "WARNING", "SQL Injection detected from IP 192.168.1.100"),
        ("2024-01-15 10:32:00", "ERROR", "Failed login attempt: admin' OR '1'='1'"),
        ("2024-01-15 10:33:45", "INFO", "File upload: malicious.php blocked"),
        ("2024-01-15 10:35:20", "CRITICAL", "XSS attempt detected in search parameter"),
        ("2024-01-15 10:36:10", "INFO", "Admin panel accessed with token"),
        ("2024-01-15 10:37:55", "WARNING", "Unusual traffic pattern detected"),
        ("2024-01-15 10:38:30", "INFO", "Database query executed: SELECT * FROM products"),
    ]
    
    logs_html = ""
    for log in logs:
        color = {"INFO": "#28a745", "WARNING": "#ffc107", "ERROR": "#fd7e14", "CRITICAL": "#dc3545"}
        logs_html += f"""
        <tr>
            <td>{log[0]}</td>
            <td><span style="color: {color.get(log[1], '#000')}; font-weight: bold;">{log[1]}</span></td>
            <td>{log[2]}</td>
        </tr>
        """
    
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>System Logs - Admin</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background: #dc3545; color: white; }}
            .nav {{ margin-bottom: 20px; }}
            .nav a {{ color: #dc3545; text-decoration: none; margin-right: 15px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="nav">
                <a href="/admin?token=admin123">← Back to Dashboard</a>
            </div>
            <h2>📊 System Logs</h2>
            <table>
                <thead>
                    <tr><th>Timestamp</th><th>Level</th><th>Message</th></tr>
                </thead>
                <tbody>
                    {logs_html}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.get("/admin/config")
async def admin_config(token: Optional[str] = None):
    """Admin configuration page"""
    if token != "admin123":
        return HTMLResponse("<h2>Access Denied</h2><p><a href='/admin'>Go to Admin Login</a></p>")
    
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Configuration - Admin</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            .config-section { margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
            input, select { padding: 8px; margin: 5px; border: 1px solid #ddd; border-radius: 3px; }
            .btn { padding: 10px 20px; background: #dc3545; color: white; border: none; border-radius: 5px; cursor: pointer; }
            .nav { margin-bottom: 20px; }
            .nav a { color: #dc3545; text-decoration: none; margin-right: 15px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="nav">
                <a href="/admin?token=admin123">← Back to Dashboard</a>
            </div>
            <h2>⚙️ System Configuration</h2>
            
            <div class="config-section">
                <h3>Security Settings</h3>
                <label>Admin Token: <input type="text" value="admin123" readonly></label><br>
                <label>Max Login Attempts: <input type="number" value="3"></label><br>
                <label>Session Timeout: <select><option>30 min</option><option>1 hour</option><option>2 hours</option></select></label>
            </div>
            
            <div class="config-section">
                <h3>Application Settings</h3>
                <label>Site Name: <input type="text" value="VulnShop"></label><br>
                <label>Debug Mode: <input type="checkbox" checked> Enabled</label><br>
                <label>Logging Level: <select><option>DEBUG</option><option>INFO</option><option>WARNING</option><option>ERROR</option></select></label>
            </div>
            
            <div class="config-section">
                <h3>Database Settings</h3>
                <label>Database File: <input type="text" value="vulnerable.db" readonly></label><br>
                <label>Backup Interval: <select><option>Daily</option><option>Weekly</option><option>Monthly</option></select></label>
            </div>
            
            <button class="btn" onclick="alert('Configuration saved!')">Save Configuration</button>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.get("/register", response_class=HTMLResponse)
async def register_form():
    """Customer registration form"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .form-group { margin: 20px 0; }
            label { display: block; margin-bottom: 8px; font-weight: bold; color: #333; }
            input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; }
            .btn { width: 100%; padding: 15px; background: #007bff; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; margin-top: 20px; }
            .btn:hover { background: #0056b3; }
            .links { text-align: center; margin-top: 20px; }
            .links a { color: #007bff; text-decoration: none; margin: 0 10px; }
            .header { text-align: center; margin-bottom: 30px; }
            .success { background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>🛍️ Join VulnShop</h2>
                <p>Create your customer account</p>
            </div>
            
            <form method="POST" action="/register">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm Password:</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>
                
                <button type="submit" class="btn">Create Account</button>
            </form>
            
            <div class="links">
                <a href="/login">Already have an account? Login</a> | 
                <a href="/">← Back to Home</a>
            </div>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.post("/register")
async def register_user(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    """Register new customer account"""
    try:
        # Basic validation
        if password != confirm_password:
            return HTMLResponse("""
            <div style="font-family: Arial; margin: 40px; text-align: center;">
                <h2>❌ Registration Failed</h2>
                <p>Passwords do not match!</p>
                <a href="/register">← Try Again</a>
            </div>
            """, status_code=400)
        
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return HTMLResponse("""
            <div style="font-family: Arial; margin: 40px; text-align: center;">
                <h2>❌ Registration Failed</h2>
                <p>Username already exists!</p>
                <a href="/register">← Try Again</a>
            </div>
            """, status_code=400)
        
        # Insert new user (non-admin by default)
        cursor.execute(
            "INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, 0)",
            (username, password, email)
        )
        conn.commit()
        conn.close()
        
        return HTMLResponse(f"""
        <div style="font-family: Arial; margin: 40px; text-align: center;">
            <h2>✅ Registration Successful!</h2>
            <p>Welcome to VulnShop, {username}!</p>
            <p>Your account has been created successfully.</p>
            <div style="margin: 30px 0;">
                <a href="/user/login" style="background: #007bff; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px;">Login to Your Account</a>
            </div>
            <p><a href="/">← Back to Home</a></p>
        </div>
        """)
        
    except Exception as e:
        return HTMLResponse(f"""
        <div style="font-family: Arial; margin: 40px; text-align: center;">
            <h2>❌ Registration Error</h2>
            <p>An error occurred: {str(e)}</p>
            <a href="/register">← Try Again</a>
        </div>
        """, status_code=500)

@vulnerable_app.get("/user/login", response_class=HTMLResponse)
async def user_login_form():
    """Customer/User login form (separate from admin)"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Customer Login - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .form-group { margin: 20px 0; }
            label { display: block; margin-bottom: 8px; font-weight: bold; color: #333; }
            input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; }
            .btn { width: 100%; padding: 15px; background: #28a745; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; }
            .btn:hover { background: #218838; }
            .links { text-align: center; margin-top: 20px; }
            .links a { color: #007bff; text-decoration: none; margin: 0 10px; }
            .header { text-align: center; margin-bottom: 30px; color: #28a745; }
            .demo-accounts { background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>🛍️ Customer Login</h2>
                <p>Access your VulnShop account</p>
            </div>
            
            <form method="POST" action="/user/login">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <button type="submit" class="btn">Login to Account</button>
            </form>
            
            <div style="text-align: center; margin: 15px 0;">
                <a href="/forgot-password" style="color: #007bff; text-decoration: none;">
                    🔑 Forgot your password?
                </a>
            </div>
            
            <div class="demo-accounts">
                <h4>Demo Accounts:</h4>
                <p><strong>Customer:</strong> user / password</p>
                <p><strong>Guest:</strong> guest / guest</p>
            </div>
            
            <div class="links">
                <a href="/register">Don't have an account? Register</a> | 
                <a href="/">← Back to Home</a>
            </div>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.post("/user/login")
async def user_login_auth(username: str = Form(...), password: str = Form(...)):
    """Customer/User authentication"""
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # Secure query (not vulnerable like admin login)
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user and user[4] == 0:  # Check if non-admin user
            # Redirect to customer dashboard
            return HTMLResponse(f"""
            <script>
                sessionStorage.setItem('vulnshop_user', '{user[1]}');
                sessionStorage.setItem('vulnshop_user_id', '{user[0]}');
                window.location.href = '/user/dashboard';
            </script>
            """)
        else:
            return HTMLResponse("""
            <div style="font-family: Arial; margin: 40px; text-align: center;">
                <h2>❌ Login Failed</h2>
                <p>Invalid credentials or admin account detected!</p>
                <p>Use <a href="/admin">Admin Panel</a> for administrative access.</p>
                <a href="/user/login">← Try Again</a>
            </div>
            """, status_code=401)
            
    except Exception as e:
        return HTMLResponse(f"""
        <div style="font-family: Arial; margin: 40px; text-align: center;">
            <h2>❌ Login Error</h2>
            <p>An error occurred: {str(e)}</p>
            <a href="/user/login">← Try Again</a>
        </div>
        """, status_code=500)


@vulnerable_app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_form():
    """Forgot password form"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Reset Password - VulnShop</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            .reset-container {
                background: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
                width: 100%;
                max-width: 450px;
                position: relative;
            }
            
            .reset-header {
                text-align: center;
                margin-bottom: 30px;
            }
            
            .reset-header h1 {
                color: #333;
                font-size: 28px;
                margin-bottom: 8px;
                font-weight: 600;
            }
            
            .reset-header p {
                color: #666;
                font-size: 14px;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            .form-group label {
                display: block;
                margin-bottom: 8px;
                color: #333;
                font-weight: 500;
                font-size: 14px;
            }
            
            .form-group input {
                width: 100%;
                padding: 12px 16px;
                border: 2px solid #e1e5e9;
                border-radius: 8px;
                font-size: 16px;
                transition: border-color 0.3s ease;
                background: #f8f9fa;
            }
            
            .form-group input:focus {
                outline: none;
                border-color: #74b9ff;
                background: white;
            }
            
            .reset-btn {
                width: 100%;
                background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
                color: white;
                padding: 14px;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s ease;
            }
            
            .reset-btn:hover {
                transform: translateY(-2px);
            }
            
            .reset-btn:active {
                transform: translateY(0);
            }
            
            .info-notice {
                background: #d1ecf1;
                border: 1px solid #bee5eb;
                color: #0c5460;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 20px;
                font-size: 14px;
            }
            
            .demo-info {
                background: #fff3cd;
                border: 1px solid #ffeaa7;
                color: #856404;
                padding: 15px;
                border-radius: 8px;
                margin-top: 20px;
                font-size: 13px;
            }
            
            .demo-info h4 {
                margin-bottom: 8px;
                font-size: 14px;
            }
            
            .back-links {
                text-align: center;
                margin-top: 20px;
                display: flex;
                justify-content: space-around;
                flex-wrap: wrap;
                gap: 10px;
            }
            
            .back-links a {
                color: #74b9ff;
                text-decoration: none;
                font-size: 14px;
                padding: 5px 10px;
            }
            
            .back-links a:hover {
                text-decoration: underline;
            }
            
            .reset-icon {
                width: 60px;
                height: 60px;
                background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 20px;
                color: white;
                font-size: 24px;
            }
        </style>
    </head>
    <body>
        <div class="reset-container">
            <div class="reset-header">
                <div class="reset-icon">🔑</div>
                <h1>Reset Password</h1>
                <p>Enter your email to reset your password</p>
            </div>
            
            <div class="info-notice">
                ℹ️ <strong>Password Reset:</strong> Enter your email address and we'll send you instructions to reset your password.
            </div>
            
            <form action="/forgot-password" method="POST">
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" placeholder="Enter your email address" required>
                </div>
                
                <button type="submit" class="reset-btn">
                    📧 Send Reset Instructions
                </button>
            </form>
            
            <div class="demo-info">
                <h4>🎯 Demo Environment:</h4>
                <p><strong>Available test emails:</strong></p>
                <p>• <code>admin@vulnshop.com</code> (Admin account)</p>
                <p>• <code>user@vulnshop.com</code> (User account)</p>
                <p>• <code>guest@vulnshop.com</code> (Guest account)</p>
            </div>
            
            <div class="back-links">
                <a href="/login">← Back to Login</a>
                <a href="/admin/login">Admin Login</a>
                <a href="/user/login">User Login</a>
                <a href="/">Home</a>
            </div>
        </div>
        
        <script>
            // Auto-focus on email field
            document.getElementById('email').focus();
        </script>
    </body>
    </html>
    """)


@vulnerable_app.post("/forgot-password")
async def forgot_password_submit(email: str = Form(...)):
    """Handle forgot password submission"""
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # Check if email exists in database
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # In a real application, you would send an email here
            # For demo purposes, we'll show the reset token
            import hashlib
            import time
            reset_token = hashlib.md5(f"{email}{time.time()}".encode()).hexdigest()[:8]
            
            return HTMLResponse(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Password Reset - VulnShop</title>
                <style>
                    body {{ font-family: Arial, sans-serif; background: #f8f9fa; padding: 40px; }}
                    .success-container {{ max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }}
                    .success-header {{ text-align: center; color: #28a745; margin-bottom: 30px; }}
                    .success-message {{ background: #d4edda; color: #155724; padding: 20px; border-radius: 8px; margin-bottom: 25px; }}
                    .reset-info {{ background: #fff3cd; color: #856404; padding: 20px; border-radius: 8px; margin-bottom: 25px; }}
                    .btn {{ display: inline-block; padding: 12px 24px; background: #007bff; color: white; text-decoration: none; border-radius: 8px; margin: 5px; }}
                    .btn:hover {{ background: #0056b3; }}
                    .demo-token {{ background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0; font-family: monospace; }}
                    .links {{ text-align: center; margin-top: 30px; }}
                </style>
            </head>
            <body>
                <div class="success-container">
                    <div class="success-header">
                        <h2>✅ Password Reset Requested</h2>
                    </div>
                    
                    <div class="success-message">
                        <strong>Success!</strong> Password reset instructions have been sent to <strong>{email}</strong>
                    </div>
                    
                    <div class="reset-info">
                        <h4>📧 What happens next:</h4>
                        <ol>
                            <li>Check your email inbox for reset instructions</li>
                            <li>Click the reset link in the email</li>
                            <li>Enter your new password</li>
                            <li>Login with your new credentials</li>
                        </ol>
                    </div>
                    
                    <div class="demo-token">
                        <strong>🔧 Demo Reset Token:</strong> <code>{reset_token}</code><br>
                        <small>In a real application, this would be sent via email.</small>
                    </div>
                    
                    <div class="links">
                        <a href="/login" class="btn">Back to Login</a>
                        <a href="/admin/login" class="btn">Admin Login</a>
                        <a href="/" class="btn" style="background: #6c757d;">Home</a>
                    </div>
                </div>
            </body>
            </html>
            """)
        else:
            # Email not found
            return HTMLResponse(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Email Not Found - VulnShop</title>
                <style>
                    body {{ font-family: Arial, sans-serif; background: #f8f9fa; padding: 40px; }}
                    .error-container {{ max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .error-header {{ color: #dc3545; text-align: center; margin-bottom: 20px; }}
                    .error-message {{ background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                    .btn {{ display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; margin: 5px; }}
                    .btn:hover {{ background: #0056b3; }}
                </style>
            </head>
            <body>
                <div class="error-container">
                    <div class="error-header">
                        <h2>❌ Email Not Found</h2>
                    </div>
                    <div class="error-message">
                        <strong>Error:</strong> The email address <strong>{email}</strong> is not registered in our system.
                    </div>
                    <p>Please check your email address and try again, or create a new account.</p>
                    <a href="/forgot-password" class="btn">← Try Again</a>
                    <a href="/register" class="btn" style="background: #28a745;">Register</a>
                    <a href="/" class="btn" style="background: #6c757d;">Home</a>
                </div>
            </body>
            </html>
            """, status_code=404)
            
    except Exception as e:
        return JSONResponse({
            "error": "Password reset system error",
            "message": str(e)
        }, status_code=500)


@vulnerable_app.get("/user/dashboard", response_class=HTMLResponse)
async def user_dashboard():
    """Customer dashboard with limited features"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>My Account - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; background: #f8f9fa; }
            .header { background: #28a745; color: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; }
            .container { max-width: 1000px; margin: 0 auto; padding: 30px; }
            .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 30px 0; }
            .card { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .card h3 { color: #28a745; margin-top: 0; }
            .btn { display: inline-block; padding: 10px 20px; background: #28a745; color: white; text-decoration: none; border-radius: 5px; margin: 5px; }
            .btn:hover { background: #218838; }
            .stats { display: flex; justify-content: space-around; background: #d1ecf1; padding: 20px; border-radius: 10px; margin: 20px 0; }
            .stat { text-align: center; }
            .stat-number { font-size: 1.5em; font-weight: bold; color: #0c5460; }
            .user-info { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
            .logout { background: #dc3545; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h1>🛍️ VulnShop - My Account</h1>
                <p>Customer Dashboard</p>
            </div>
            <button class="logout" onclick="logout()">Logout</button>
        </div>
        
        <div class="container">
            <div class="user-info">
                <h3>👤 Welcome, <span id="username">Customer</span>!</h3>
                <p>Account ID: <span id="user-id">-</span> | Account Type: Customer</p>
            </div>
            
            <div class="stats">
                <div class="stat">
                    <div class="stat-number">5</div>
                    <div>Orders</div>
                </div>
                <div class="stat">
                    <div class="stat-number">$299.99</div>
                    <div>Total Spent</div>
                </div>
                <div class="stat">
                    <div class="stat-number">2</div>
                    <div>Cart Items</div>
                </div>
                <div class="stat">
                    <div class="stat-number">Gold</div>
                    <div>Member Status</div>
                </div>
            </div>
            
            <div class="dashboard-grid">
                <div class="card">
                    <h3>🛒 My Orders</h3>
                    <p>View your order history and track current shipments.</p>
                    <a href="/user/orders" class="btn">View Orders</a>
                </div>
                
                <div class="card">
                    <h3>👤 Profile Settings</h3>
                    <p>Update your personal information and account preferences.</p>
                    <a href="/user/profile" class="btn">Edit Profile</a>
                </div>
                
                <div class="card">
                    <h3>🛍️ Browse Products</h3>
                    <p>Explore our catalog and add items to your cart.</p>
                    <a href="/products" class="btn">Shop Now</a>
                </div>
                
                <div class="card">
                    <h3>💰 Payment Methods</h3>
                    <p>Manage your saved payment options and billing addresses.</p>
                    <a href="/user/payments" class="btn">Manage Payments</a>
                </div>
                
                <div class="card">
                    <h3>📧 Contact Support</h3>
                    <p>Get help with your orders or account issues.</p>
                    <a href="/contact" class="btn">Contact Us</a>
                </div>
                
                <div class="card">
                    <h3>🔐 Security</h3>
                    <p>Change your password and review account security.</p>
                    <a href="/user/security" class="btn">Security Settings</a>
                </div>
            </div>
        </div>
        
        <script>
            // Load user info from session storage
            const username = sessionStorage.getItem('vulnshop_user');
            const userId = sessionStorage.getItem('vulnshop_user_id');
            
            if (username) {
                document.getElementById('username').textContent = username;
                document.getElementById('user-id').textContent = userId || 'Unknown';
            } else {
                // Redirect to login if no session
                window.location.href = '/user/login';
            }
            
            function logout() {
                sessionStorage.removeItem('vulnshop_user');
                sessionStorage.removeItem('vulnshop_user_id');
                alert('Logged out successfully!');
                window.location.href = '/';
            }
        </script>
    </body>
    </html>
    """)

@vulnerable_app.get("/user/profile", response_class=HTMLResponse)
async def user_profile():
    """User profile management page"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>My Profile - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; background: #f8f9fa; }
            .header { background: #28a745; color: white; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; padding: 30px; }
            .profile-card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin: 20px 0; }
            .form-group { margin: 20px 0; }
            label { display: block; margin-bottom: 8px; font-weight: bold; color: #333; }
            input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px; }
            .btn { padding: 12px 25px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; margin: 10px 5px; }
            .btn-secondary { background: #6c757d; }
            .nav { margin-bottom: 20px; }
            .nav a { color: #28a745; text-decoration: none; margin-right: 15px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>👤 My Profile</h1>
            <p>Manage your account information</p>
        </div>
        
        <div class="container">
            <div class="nav">
                <a href="/user/dashboard">← Back to Dashboard</a>
            </div>
            
            <div class="profile-card">
                <h3>Personal Information</h3>
                <form method="POST" action="/user/profile/update">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" readonly>
                    </div>
                    
                    <div class="form-group">
                        <label for="email">Email Address:</label>
                        <input type="email" id="email" name="email">
                    </div>
                    
                    <div class="form-group">
                        <label for="full_name">Full Name:</label>
                        <input type="text" id="full_name" name="full_name" placeholder="Enter your full name">
                    </div>
                    
                    <div class="form-group">
                        <label for="phone">Phone Number:</label>
                        <input type="tel" id="phone" name="phone" placeholder="Enter your phone number">
                    </div>
                    
                    <div class="form-group">
                        <label for="address">Address:</label>
                        <input type="text" id="address" name="address" placeholder="Enter your address">
                    </div>
                    
                    <button type="submit" class="btn">Update Profile</button>
                    <button type="button" class="btn btn-secondary" onclick="loadUserData()">Reset</button>
                </form>
            </div>
            
            <div class="profile-card">
                <h3>Account Security</h3>
                <p>Last Login: <span id="last-login">Today</span></p>
                <p>Account Created: <span id="account-created">Recently</span></p>
                <a href="/user/security" class="btn">Change Password</a>
            </div>
        </div>
        
        <script>
            function loadUserData() {
                const username = sessionStorage.getItem('vulnshop_user');
                if (username) {
                    document.getElementById('username').value = username;
                    // Load additional user data would go here
                } else {
                    window.location.href = '/user/login';
                }
            }
            
            // Load user data on page load
            loadUserData();
        </script>
    </body>
    </html>
    """)

@vulnerable_app.post("/user/profile/update")
async def update_user_profile(
    username: str = Form(...),
    email: str = Form(...),
    full_name: str = Form(None),
    phone: str = Form(None),
    address: str = Form(None)
):
    """Update user profile information"""
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        # Update email in users table
        cursor.execute("UPDATE users SET email = ? WHERE username = ?", (email, username))
        
        # Note: In a real app, you'd have a separate profile table for additional info
        # For simplicity, we'll just update the email
        
        conn.commit()
        conn.close()
        
        return HTMLResponse("""
        <div style="font-family: Arial; margin: 40px; text-align: center;">
            <h2>✅ Profile Updated!</h2>
            <p>Your profile information has been updated successfully.</p>
            <a href="/user/profile" style="background: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px;">Back to Profile</a>
        </div>
        """)
        
    except Exception as e:
        return HTMLResponse(f"""
        <div style="font-family: Arial; margin: 40px; text-align: center;">
            <h2>❌ Update Failed</h2>
            <p>Error: {str(e)}</p>
            <a href="/user/profile">← Back to Profile</a>
        </div>
        """, status_code=500)

@vulnerable_app.get("/user/orders", response_class=HTMLResponse)
async def user_orders():
    """User orders page"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>My Orders - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; background: #f8f9fa; }
            .header { background: #28a745; color: white; padding: 20px; }
            .container { max-width: 1000px; margin: 0 auto; padding: 30px; }
            .order-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin: 15px 0; }
            .order-status { padding: 5px 15px; border-radius: 15px; color: white; font-size: 12px; }
            .status-delivered { background: #28a745; }
            .status-shipped { background: #007bff; }
            .status-processing { background: #ffc107; color: #000; }
            .nav { margin-bottom: 20px; }
            .nav a { color: #28a745; text-decoration: none; margin-right: 15px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>📦 My Orders</h1>
            <p>Track your purchase history</p>
        </div>
        
        <div class="container">
            <div class="nav">
                <a href="/user/dashboard">← Back to Dashboard</a>
            </div>
            
            <div class="order-card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h4>Order #1001</h4>
                        <p>Placed on: January 15, 2024</p>
                    </div>
                    <span class="order-status status-delivered">Delivered</span>
                </div>
                <p><strong>Items:</strong> Premium Laptop, Wireless Mouse</p>
                <p><strong>Total:</strong> $1,099.98</p>
            </div>
            
            <div class="order-card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h4>Order #1002</h4>
                        <p>Placed on: January 20, 2024</p>
                    </div>
                    <span class="order-status status-shipped">Shipped</span>
                </div>
                <p><strong>Items:</strong> Smartphone Case, Screen Protector</p>
                <p><strong>Total:</strong> $39.99</p>
            </div>
            
            <div class="order-card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h4>Order #1003</h4>
                        <p>Placed on: January 22, 2024</p>
                    </div>
                    <span class="order-status status-processing">Processing</span>
                </div>
                <p><strong>Items:</strong> Tablet, Stylus Pen</p>
                <p><strong>Total:</strong> $449.99</p>
            </div>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.get("/contact")
async def contact_form():
    """Contact form with XSS vulnerability"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Contact Us - VulnShop</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            .warning { background: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>📧 Contact Us</h2>
            <div class="warning">
                ⚠️ This form is vulnerable to XSS attacks!
            </div>
            
            <form method="POST" action="/contact">
                <div style="margin: 15px 0;">
                    <label>Name:</label><br>
                    <input type="text" name="name" style="width: 100%; padding: 10px;">
                </div>
                <div style="margin: 15px 0;">
                    <label>Message:</label><br>
                    <textarea name="message" style="width: 100%; padding: 10px; height: 100px;"></textarea>
                </div>
                <button type="submit" style="padding: 12px 24px; background: #007bff; color: white; border: none; border-radius: 5px;">Send Message</button>
            </form>
            
            <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
                <h4>🎯 XSS Attack Examples:</h4>
                <ul>
                    <li><code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                    <li><code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
                    <li><code>&lt;svg onload=alert('XSS')&gt;&lt;/svg&gt;</code></li>
                </ul>
            </div>
            
            <p><a href="/">← Back to Home</a></p>
        </div>
    </body>
    </html>
    """)

@vulnerable_app.post("/contact")
async def vulnerable_contact(name: str = Form(...), message: str = Form(...)):
    """Vulnerable contact form that reflects input without sanitization"""
    # VULNERABLE: Direct reflection without sanitization
    response_html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Message Received</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h2>✅ Message Received!</h2>
        <div style="background: #d4edda; padding: 20px; border-radius: 5px;">
            <p><strong>From:</strong> {name}</p>
            <p><strong>Message:</strong> {message}</p>
        </div>
        <p><a href="/contact">← Send Another Message</a></p>
        <p><a href="/">← Back to Home</a></p>
    </body>
    </html>
    """
    return HTMLResponse(response_html)

# Health check endpoint
@vulnerable_app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "app": "VulnShop", "purpose": "WAF Testing Target"}

def find_available_port(start_port=8080, max_attempts=10):
    """Find an available port starting from start_port"""
    import socket
    
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    return None

if __name__ == "__main__":
    print("🎯 Starting Vulnerable Web Application for WAF Testing")
    print("⚠️  WARNING: This application contains intentional vulnerabilities!")
    print("🔥 DO NOT USE IN PRODUCTION")
    
    # Find available port
    available_port = find_available_port(8080)
    if available_port is None:
        print("❌ ERROR: Could not find an available port between 8080-8089")
        print("� Solution: Close other applications using these ports")
        exit(1)
    
    print(f"�📡 Server will start on http://localhost:{available_port}")
    
    if available_port != 8080:
        print(f"ℹ️  Note: Using port {available_port} instead of 8080 (port was in use)")
        print(f"📝 Update your WAF proxy to use: http://localhost:{available_port}")
    
    import uvicorn
    uvicorn.run(vulnerable_app, host="127.0.0.1", port=8080)
