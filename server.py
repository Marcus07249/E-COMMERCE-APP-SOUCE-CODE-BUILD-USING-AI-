from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
from passlib.context import CryptContext
from bson import ObjectId

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")

JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    name: str
    role: str = "user"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Product(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    price: float
    category: str
    image: str
    stock: int = 100
    featured: bool = False
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ProductCreate(BaseModel):
    name: str
    description: str
    price: float
    category: str
    image: str
    stock: int = 100
    featured: bool = False

class Category(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    slug: str
    image: str
    description: str

class CategoryCreate(BaseModel):
    name: str
    slug: str
    image: str
    description: str

class CartItem(BaseModel):
    product_id: str
    quantity: int

class Cart(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_id: str
    items: List[CartItem]
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class OrderItem(BaseModel):
    product_id: str
    product_name: str
    quantity: int
    price: float

class Order(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    items: List[OrderItem]
    total: float
    address: dict
    payment_method: str
    status: str = "pending"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class OrderCreate(BaseModel):
    items: List[OrderItem]
    total: float
    address: dict
    payment_method: str

class SiteSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")
    theme_colors: dict = {"primary": "#FACC15", "background": "#09090b"}
    payment_methods: dict = {"upi": True, "card": True, "cod": True}

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

@api_router.post("/auth/signup")
async def signup(user_data: UserCreate):
    existing = await db.users.find_one({"email": user_data.email}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user = User(
        email=user_data.email,
        name=user_data.name,
        role="user"
    )
    doc = user.model_dump()
    doc["password_hash"] = hash_password(user_data.password)
    
    await db.users.insert_one(doc)
    token = create_token(user.id, user.email, user.role)
    
    return {"token": token, "user": user}

@api_router.post("/auth/login")
async def login(login_data: UserLogin):
    user_doc = await db.users.find_one({"email": login_data.email}, {"_id": 0})
    if not user_doc:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(login_data.password, user_doc["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user = User(**user_doc)
    token = create_token(user.id, user.email, user.role)
    
    return {"token": token, "user": user}

@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    user_doc = await db.users.find_one({"id": current_user["user_id"]}, {"_id": 0})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    return User(**user_doc)

@api_router.get("/products", response_model=List[Product])
async def get_products(category: Optional[str] = None, search: Optional[str] = None):
    query = {}
    if category:
        query["category"] = category
    if search:
        query["name"] = {"$regex": search, "$options": "i"}
    
    products = await db.products.find(query, {"_id": 0}).to_list(1000)
    return products

@api_router.get("/products/featured", response_model=List[Product])
async def get_featured_products():
    products = await db.products.find({"featured": True}, {"_id": 0}).to_list(20)
    return products

@api_router.get("/products/{product_id}", response_model=Product)
async def get_product(product_id: str):
    product = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

@api_router.post("/products", response_model=Product)
async def create_product(product_data: ProductCreate, admin: dict = Depends(get_admin_user)):
    product = Product(**product_data.model_dump())
    await db.products.insert_one(product.model_dump())
    return product

@api_router.put("/products/{product_id}", response_model=Product)
async def update_product(product_id: str, product_data: ProductCreate, admin: dict = Depends(get_admin_user)):
    result = await db.products.update_one(
        {"id": product_id},
        {"$set": product_data.model_dump()}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    
    updated = await db.products.find_one({"id": product_id}, {"_id": 0})
    return Product(**updated)

@api_router.delete("/products/{product_id}")
async def delete_product(product_id: str, admin: dict = Depends(get_admin_user)):
    result = await db.products.delete_one({"id": product_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"message": "Product deleted"}

@api_router.get("/categories", response_model=List[Category])
async def get_categories():
    categories = await db.categories.find({}, {"_id": 0}).to_list(100)
    return categories

@api_router.post("/categories", response_model=Category)
async def create_category(category_data: CategoryCreate, admin: dict = Depends(get_admin_user)):
    category = Category(**category_data.model_dump())
    await db.categories.insert_one(category.model_dump())
    return category

@api_router.put("/categories/{category_id}", response_model=Category)
async def update_category(category_id: str, category_data: CategoryCreate, admin: dict = Depends(get_admin_user)):
    result = await db.categories.update_one(
        {"id": category_id},
        {"$set": category_data.model_dump()}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Category not found")
    
    updated = await db.categories.find_one({"id": category_id}, {"_id": 0})
    return Category(**updated)

@api_router.delete("/categories/{category_id}")
async def delete_category(category_id: str, admin: dict = Depends(get_admin_user)):
    result = await db.categories.delete_one({"id": category_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Category not found")
    return {"message": "Category deleted"}

@api_router.get("/cart")
async def get_cart(current_user: dict = Depends(get_current_user)):
    cart = await db.carts.find_one({"user_id": current_user["user_id"]}, {"_id": 0})
    if not cart:
        return {"user_id": current_user["user_id"], "items": []}
    return cart

@api_router.post("/cart")
async def update_cart(cart_data: Cart, current_user: dict = Depends(get_current_user)):
    await db.carts.update_one(
        {"user_id": current_user["user_id"]},
        {"$set": cart_data.model_dump()},
        upsert=True
    )
    return cart_data

@api_router.post("/orders", response_model=Order)
async def create_order(order_data: OrderCreate, current_user: dict = Depends(get_current_user)):
    order = Order(
        user_id=current_user["user_id"],
        **order_data.model_dump()
    )
    await db.orders.insert_one(order.model_dump())
    
    await db.carts.delete_one({"user_id": current_user["user_id"]})
    
    return order

@api_router.get("/orders", response_model=List[Order])
async def get_orders(current_user: dict = Depends(get_current_user)):
    orders = await db.orders.find({"user_id": current_user["user_id"]}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return orders

@api_router.get("/admin/orders", response_model=List[Order])
async def get_all_orders(admin: dict = Depends(get_admin_user)):
    orders = await db.orders.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return orders

@api_router.put("/admin/orders/{order_id}")
async def update_order_status(order_id: str, status: str, admin: dict = Depends(get_admin_user)):
    result = await db.orders.update_one(
        {"id": order_id},
        {"$set": {"status": status}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"message": "Order updated"}

@api_router.get("/admin/users", response_model=List[User])
async def get_all_users(admin: dict = Depends(get_admin_user)):
    users = await db.users.find({}, {"_id": 0, "password_hash": 0}).to_list(1000)
    return users

@api_router.get("/settings")
async def get_settings():
    settings = await db.site_settings.find_one({}, {"_id": 0})
    if not settings:
        default_settings = SiteSettings()
        await db.site_settings.insert_one(default_settings.model_dump())
        return default_settings
    return settings

@api_router.put("/admin/settings")
async def update_settings(settings: SiteSettings, admin: dict = Depends(get_admin_user)):
    await db.site_settings.update_one(
        {},
        {"$set": settings.model_dump()},
        upsert=True
    )
    return settings

@api_router.post("/init-data")
async def initialize_data():
    existing_admin = await db.users.find_one({"email": "admin@shop.com"})
    if not existing_admin:
        admin = User(email="admin@shop.com", name="Admin", role="admin")
        admin_doc = admin.model_dump()
        admin_doc["password_hash"] = hash_password("admin123")
        await db.users.insert_one(admin_doc)
    
    existing_categories = await db.categories.count_documents({})
    if existing_categories == 0:
        categories = [
            {"id": str(uuid.uuid4()), "name": "Electronics", "slug": "electronics", "image": "https://images.unsplash.com/photo-1605170876472-db58e15c430e?crop=entropy&cs=srgb&fm=jpg&q=85", "description": "Latest gadgets and tech"},
            {"id": str(uuid.uuid4()), "name": "Accessories", "slug": "accessories", "image": "https://images.unsplash.com/photo-1673997303871-178507ca875a?crop=entropy&cs=srgb&fm=jpg&q=85", "description": "Fashion accessories"},
            {"id": str(uuid.uuid4()), "name": "Kitchen", "slug": "kitchen", "image": "https://images.unsplash.com/photo-1556911220-bff31c812dba?crop=entropy&cs=srgb&fm=jpg&q=85", "description": "Kitchen essentials"},
            {"id": str(uuid.uuid4()), "name": "Furniture", "slug": "furniture", "image": "https://images.unsplash.com/photo-1723804685588-b8e95b2044f3?crop=entropy&cs=srgb&fm=jpg&q=85", "description": "Modern furniture"},
            {"id": str(uuid.uuid4()), "name": "Fashion", "slug": "fashion", "image": "https://images.unsplash.com/photo-1542755687-a33ff0c970ec?crop=entropy&cs=srgb&fm=jpg&q=85", "description": "Trendy clothing"},
            {"id": str(uuid.uuid4()), "name": "Others", "slug": "others", "image": "https://images.unsplash.com/photo-1550989460-0adf9ea622e2?crop=entropy&cs=srgb&fm=jpg&q=85", "description": "Miscellaneous items"}
        ]
        await db.categories.insert_many(categories)
    
    existing_products = await db.products.count_documents({})
    if existing_products == 0:
        products = [
            {"id": str(uuid.uuid4()), "name": "Wireless Headphones", "description": "Premium noise-canceling headphones", "price": 199.99, "category": "electronics", "image": "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=500", "stock": 50, "featured": True},
            {"id": str(uuid.uuid4()), "name": "Smart Watch", "description": "Fitness tracking smartwatch", "price": 299.99, "category": "electronics", "image": "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=500", "stock": 30, "featured": True},
            {"id": str(uuid.uuid4()), "name": "Laptop Stand", "description": "Ergonomic aluminum laptop stand", "price": 49.99, "category": "electronics", "image": "https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?w=500", "stock": 100, "featured": False},
            {"id": str(uuid.uuid4()), "name": "Mechanical Keyboard", "description": "RGB gaming keyboard", "price": 129.99, "category": "electronics", "image": "https://images.unsplash.com/photo-1587829741301-dc798b83add3?w=500", "stock": 45, "featured": True},
            {"id": str(uuid.uuid4()), "name": "Wireless Mouse", "description": "Ergonomic wireless mouse", "price": 39.99, "category": "electronics", "image": "https://images.unsplash.com/photo-1527814050087-3793815479db?w=500", "stock": 80, "featured": False},
            {"id": str(uuid.uuid4()), "name": "Leather Wallet", "description": "Genuine leather bifold wallet", "price": 59.99, "category": "accessories", "image": "https://images.unsplash.com/photo-1627123424574-724758594e93?w=500", "stock": 60, "featured": True},
            {"id": str(uuid.uuid4()), "name": "Sunglasses", "description": "Classic aviator sunglasses", "price": 89.99, "category": "accessories", "image": "https://images.unsplash.com/photo-1572635196237-14b3f281503f?w=500", "stock": 70, "featured": False},
            {"id": str(uuid.uuid4()), "name": "Backpack", "description": "Durable travel backpack", "price": 79.99, "category": "accessories", "image": "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=500", "stock": 40, "featured": True},
            {"id": str(uuid.uuid4()), "name": "Coffee Maker", "description": "Automatic drip coffee maker", "price": 149.99, "category": "kitchen", "image": "https://images.unsplash.com/photo-1517668808822-9ebb02f2a0e6?w=500", "stock": 25, "featured": False},
            {"id": str(uuid.uuid4()), "name": "Blender", "description": "High-speed professional blender", "price": 99.99, "category": "kitchen", "image": "https://images.unsplash.com/photo-1585515320310-259814833e62?w=500", "stock": 35, "featured": True},
            {"id": str(uuid.uuid4()), "name": "Knife Set", "description": "Professional chef knife set", "price": 159.99, "category": "kitchen", "image": "https://images.unsplash.com/photo-1593618998160-e34014e67546?w=500", "stock": 20, "featured": False},
            {"id": str(uuid.uuid4()), "name": "Office Chair", "description": "Ergonomic mesh office chair", "price": 349.99, "category": "furniture", "image": "https://images.unsplash.com/photo-1580480055273-228ff5388ef8?w=500", "stock": 15, "featured": True},
            {"id": str(uuid.uuid4()), "name": "Standing Desk", "description": "Adjustable height standing desk", "price": 499.99, "category": "furniture", "image": "https://images.unsplash.com/photo-1595515106969-1ce29566ff1c?w=500", "stock": 10, "featured": True},
            {"id": str(uuid.uuid4()), "name": "Bookshelf", "description": "Modern 5-tier bookshelf", "price": 199.99, "category": "furniture", "image": "https://images.unsplash.com/photo-1594620302200-9a762244a156?w=500", "stock": 18, "featured": False},
            {"id": str(uuid.uuid4()), "name": "T-Shirt", "description": "Cotton casual t-shirt", "price": 29.99, "category": "fashion", "image": "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=500", "stock": 100, "featured": False},
            {"id": str(uuid.uuid4()), "name": "Jeans", "description": "Classic slim fit jeans", "price": 79.99, "category": "fashion", "image": "https://images.unsplash.com/photo-1542272604-787c3835535d?w=500", "stock": 90, "featured": True},
            {"id": str(uuid.uuid4()), "name": "Sneakers", "description": "Comfortable running sneakers", "price": 119.99, "category": "fashion", "image": "https://images.unsplash.com/photo-1460353581641-37baddab0fa2?w=500", "stock": 50, "featured": True},
            {"id": str(uuid.uuid4()), "name": "Hoodie", "description": "Warm pullover hoodie", "price": 69.99, "category": "fashion", "image": "https://images.unsplash.com/photo-1556821840-3a63f95609a7?w=500", "stock": 65, "featured": False},
            {"id": str(uuid.uuid4()), "name": "Phone Case", "description": "Protective silicone phone case", "price": 19.99, "category": "others", "image": "https://images.unsplash.com/photo-1601784551446-20c9e07cdbdb?w=500", "stock": 150, "featured": False},
            {"id": str(uuid.uuid4()), "name": "Water Bottle", "description": "Insulated stainless steel bottle", "price": 34.99, "category": "others", "image": "https://images.unsplash.com/photo-1602143407151-7111542de6e8?w=500", "stock": 120, "featured": False},
            {"id": str(uuid.uuid4()), "name": "Yoga Mat", "description": "Non-slip exercise yoga mat", "price": 44.99, "category": "others", "image": "https://images.unsplash.com/photo-1601925260368-ae2f83cf8b7f?w=500", "stock": 75, "featured": True},
            {"id": str(uuid.uuid4()), "name": "Desk Lamp", "description": "LED adjustable desk lamp", "price": 54.99, "category": "others", "image": "https://images.unsplash.com/photo-1507473885765-e6ed057f782c?w=500", "stock": 55, "featured": False},
            {"id": str(uuid.uuid4()), "name": "Power Bank", "description": "20000mAh portable charger", "price": 49.99, "category": "electronics", "image": "https://images.unsplash.com/photo-1609091839311-d5365f9ff1c5?w=500", "stock": 85, "featured": False},
            {"id": str(uuid.uuid4()), "name": "USB-C Cable", "description": "Fast charging USB-C cable", "price": 14.99, "category": "electronics", "image": "https://images.unsplash.com/photo-1625948515291-69613efd103f?w=500", "stock": 200, "featured": False},
            {"id": str(uuid.uuid4()), "name": "Webcam", "description": "1080p HD streaming webcam", "price": 89.99, "category": "electronics", "image": "https://images.unsplash.com/photo-1588508065123-287b28e013da?w=500", "stock": 40, "featured": True},
            {"id": str(uuid.uuid4()), "name": "Microphone", "description": "USB condenser microphone", "price": 129.99, "category": "electronics", "image": "https://images.unsplash.com/photo-1590602847861-f357a9332bbc?w=500", "stock": 30, "featured": False},
            {"id": str(uuid.uuid4()), "name": "Monitor", "description": "27-inch 4K monitor", "price": 399.99, "category": "electronics", "image": "https://images.unsplash.com/photo-1527443224154-c4a3942d3acf?w=500", "stock": 20, "featured": True},
            {"id": str(uuid.uuid4()), "name": "Tablet", "description": "10-inch Android tablet", "price": 299.99, "category": "electronics", "image": "https://images.unsplash.com/photo-1561154464-82e9adf32764?w=500", "stock": 25, "featured": True},
            {"id": str(uuid.uuid4()), "name": "Gaming Mouse Pad", "description": "Extended RGB mouse pad", "price": 29.99, "category": "electronics", "image": "https://images.unsplash.com/photo-1615663245857-ac93bb7c39e7?w=500", "stock": 95, "featured": False},
            {"id": str(uuid.uuid4()), "name": "Speaker System", "description": "2.1 desktop speaker system", "price": 149.99, "category": "electronics", "image": "https://images.unsplash.com/photo-1608043152269-423dbba4e7e1?w=500", "stock": 35, "featured": False}
        ]
        await db.products.insert_many(products)
    
    return {"message": "Data initialized"}

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()