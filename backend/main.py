from fastapi import FastAPI, HTTPException, Depends, status, Request, APIRouter, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, EmailStr
import uvicorn
from typing import Optional, List, Dict, Any
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
import os
import json
import shutil
import uuid

# 密钥配置
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 密码加密配置
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# 确保tokenUrl与实际路由一致
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# 数据模型
class UserCreate(BaseModel):
    username: str
    password: str
    email: Optional[EmailStr] = None

class UserLogin(BaseModel):
    username: str
    password: str

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    disabled: Optional[bool] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    email: Optional[EmailStr] = None
    disabled: bool = False

# 小说相关的模型
class NovelCreate(BaseModel):
    title: str
    description: str
    genre: str
    tags: List[str]

class ChapterCreate(BaseModel):
    title: str
    content: str

class NovelUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    genre: Optional[str] = None
    tags: Optional[List[str]] = None

class ChapterUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None

# 世界观相关的模型
class WorldCreate(BaseModel):
    name: str
    description: str
    setting: str
    time_period: Optional[str] = None
    rules: Optional[List[str]] = None

class WorldUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    setting: Optional[str] = None
    time_period: Optional[str] = None
    rules: Optional[List[str]] = None

class LocationCreate(BaseModel):
    name: str
    description: str
    characteristics: Optional[List[str]] = None

class EventCreate(BaseModel):
    name: str
    description: str
    time: str
    significance: Optional[str] = None

# 角色相关的模型
class CharacterCreate(BaseModel):
    name: str
    description: str
    age: Optional[int] = None
    gender: Optional[str] = None
    background: Optional[str] = None
    personality: Optional[List[str]] = None
    goals: Optional[List[str]] = None

class CharacterUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    age: Optional[int] = None
    gender: Optional[str] = None
    background: Optional[str] = None
    personality: Optional[List[str]] = None
    goals: Optional[List[str]] = None

class RelationshipCreate(BaseModel):
    target_character_id: str
    relationship_type: str
    description: Optional[str] = None

class DialogueCreate(BaseModel):
    content: str
    context: Optional[str] = None
    tone: Optional[str] = None

# 知识库相关的模型
class KnowledgeBaseCreate(BaseModel):
    name: str
    description: str
    type: str = "general"  # general, historical, scientific, etc.

class KnowledgeBaseUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    type: Optional[str] = None

class KnowledgeEntryCreate(BaseModel):
    title: str
    content: str
    source: Optional[str] = None
    tags: Optional[List[str]] = None

class KnowledgeSearch(BaseModel):
    query: str
    limit: int = 10

class KnowledgeRecommend(BaseModel):
    context: str
    limit: int = 5

# 文件相关的模型
class FileInfo(BaseModel):
    file_id: str
    filename: str
    type: str
    description: Optional[str] = None
    size: int
    created_at: str
    updated_at: str
    author_id: str

# 模拟数据库
users_db = {}
novels_db = {}
chapters_db = {}
worlds_db = {}
locations_db = {}
events_db = {}
characters_db = {}
relationships_db = {}
dialogues_db = {}
knowledge_bases_db = {}
knowledge_entries_db = {}
files_db = {}

# 文件存储目录
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 辅助函数
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证密码"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """生成密码哈希"""
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    """验证用户"""
    if username not in users_db:
        return False
    user = users_db[username]
    if not verify_password(password, user["password"]):
        return False
    return user

def create_access_token(data: dict):
    """创建访问令牌"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 依赖项
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """获取当前用户"""
    credentials_exception = HTTPException(
        status_code=401,
        detail="无效的认证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.JWTError:
        raise credentials_exception

    user = users_db.get(username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    """获取当前活跃用户"""
    if current_user.get("disabled"):
        raise HTTPException(status_code=400, detail="用户已禁用")
    return current_user

# 创建FastAPI应用
app = FastAPI(title="小说创作辅助系统", version="1.0.0")

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 基础API路由
@app.get("/")
async def read_root():
    """API根路径"""
    return {"message": "小说创作辅助系统API服务已启动"}

@app.get("/api/health")
async def health_check():
    """健康检查"""
    return {"status": "healthy", "service": "novel-backend"}

# 用户认证路由
@app.post("/api/auth/register")
async def register(user: UserCreate):
    """用户注册"""
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="用户名已存在")

    hashed_password = get_password_hash(user.password)
    users_db[user.username] = {
        "username": user.username,
        "password": hashed_password,
        "email": user.email,
        "disabled": False
    }

    return {"message": "注册成功", "username": user.username}

@app.post("/api/auth/login")
async def login(user: UserLogin):
    """用户登录"""
    user_data = authenticate_user(user.username, user.password)
    if not user_data:
        raise HTTPException(
            status_code=400,
            detail="密码错误"
        )

    access_token = create_access_token({"sub": user.username})
    return Token(access_token=access_token, token_type="bearer")

# 小说相关路由
@app.post("/api/novels")
async def create_novel(novel: NovelCreate, current_user: dict = Depends(get_current_active_user)):
    """创建新小说"""
    novel_id = str(len(novels_db) + 1)
    novel_data = novel.model_dump()
    novel_data.update({
        "id": novel_id,
        "author_id": current_user["username"],
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    })
    novels_db[novel_id] = novel_data
    return novel_data

@app.get("/api/novels/{novel_id}")
async def get_novel(novel_id: str, current_user: dict = Depends(get_current_active_user)):
    """获取小说详情"""
    if novel_id not in novels_db:
        raise HTTPException(status_code=404, detail="小说不存在")
    novel = novels_db[novel_id]
    if novel["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权访问此小说")
    return novel

@app.put("/api/novels/{novel_id}")
async def update_novel(
    novel_id: str,
    novel_update: NovelUpdate,
    current_user: dict = Depends(get_current_active_user)
):
    """更新小说信息"""
    if novel_id not in novels_db:
        raise HTTPException(status_code=404, detail="小说不存在")
    novel = novels_db[novel_id]
    if novel["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权修改此小说")

    update_data = novel_update.model_dump(exclude_unset=True)
    novel.update(update_data)
    novel["updated_at"] = datetime.utcnow().isoformat()
    novels_db[novel_id] = novel
    return {"message": "小说信息更新成功"}

@app.delete("/api/novels/{novel_id}")
async def delete_novel(novel_id: str, current_user: dict = Depends(get_current_active_user)):
    """删除小说"""
    if novel_id not in novels_db:
        raise HTTPException(status_code=404, detail="小说不存在")
    novel = novels_db[novel_id]
    if novel["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权删除此小说")

    del novels_db[novel_id]
    # 删除相关章节
    chapters_to_delete = [
        chapter_id for chapter_id, chapter in chapters_db.items()
        if chapter["novel_id"] == novel_id
    ]
    for chapter_id in chapters_to_delete:
        del chapters_db[chapter_id]
    return {"message": "小说删除成功"}

@app.post("/api/novels/{novel_id}/chapters")
async def create_chapter(
    novel_id: str,
    chapter: ChapterCreate,
    current_user: dict = Depends(get_current_active_user)
):
    """创建新章节"""
    if novel_id not in novels_db:
        raise HTTPException(status_code=404, detail="小说不存在")
    novel = novels_db[novel_id]
    if novel["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权在此小说中创建章节")

    chapter_id = f"{novel_id}_chapter_{len(chapters_db) + 1}"
    chapter_data = chapter.model_dump()
    chapter_data.update({
        "id": chapter_id,
        "novel_id": novel_id,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    })
    chapters_db[chapter_id] = chapter_data
    return chapter_data

@app.get("/api/novels/{novel_id}/chapters")
async def list_chapters(novel_id: str, current_user: dict = Depends(get_current_active_user)):
    """获取小说的章节列表"""
    if novel_id not in novels_db:
        raise HTTPException(status_code=404, detail="小说不存在")
    novel = novels_db[novel_id]
    if novel["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权访问此小说的章节")

    novel_chapters = [
        chapter for chapter in chapters_db.values()
        if chapter["novel_id"] == novel_id
    ]
    return novel_chapters

@app.put("/api/novels/{novel_id}/chapters/{chapter_id}")
async def update_chapter(
    novel_id: str,
    chapter_id: str,
    chapter_update: ChapterUpdate,
    current_user: dict = Depends(get_current_active_user)
):
    """更新章节内容"""
    if novel_id not in novels_db:
        raise HTTPException(status_code=404, detail="小说不存在")
    if chapter_id not in chapters_db:
        raise HTTPException(status_code=404, detail="章节不存在")

    novel = novels_db[novel_id]
    chapter = chapters_db[chapter_id]

    if novel["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权修改此章节")
    if chapter["novel_id"] != novel_id:
        raise HTTPException(status_code=400, detail="章节不属于此小说")

    update_data = chapter_update.model_dump(exclude_unset=True)
    chapter.update(update_data)
    chapter["updated_at"] = datetime.utcnow().isoformat()
    chapters_db[chapter_id] = chapter
    return {"message": "章节更新成功"}

@app.delete("/api/novels/{novel_id}/chapters/{chapter_id}")
async def delete_chapter(
    novel_id: str,
    chapter_id: str,
    current_user: dict = Depends(get_current_active_user)
):
    """删除章节"""
    if novel_id not in novels_db:
        raise HTTPException(status_code=404, detail="小说不存在")
    if chapter_id not in chapters_db:
        raise HTTPException(status_code=404, detail="章节不存在")

    novel = novels_db[novel_id]
    chapter = chapters_db[chapter_id]

    if novel["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权删除此章节")
    if chapter["novel_id"] != novel_id:
        raise HTTPException(status_code=400, detail="章节不属于此小说")

    del chapters_db[chapter_id]
    return {"message": "章节删除成功"}

# 世界观相关路由
@app.post("/api/worlds")
async def create_world(world: WorldCreate, current_user: dict = Depends(get_current_active_user)):
    """创建新世界观"""
    world_id = str(len(worlds_db) + 1)
    world_data = world.model_dump()
    world_data.update({
        "id": world_id,
        "author_id": current_user["username"],
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    })
    worlds_db[world_id] = world_data
    return world_data

@app.get("/api/worlds/{world_id}")
async def get_world(world_id: str, current_user: dict = Depends(get_current_active_user)):
    """获取世界观详情"""
    if world_id not in worlds_db:
        raise HTTPException(status_code=404, detail="世界观不存在")
    world = worlds_db[world_id]
    if world["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权访问此世界观")
    return world

@app.put("/api/worlds/{world_id}")
async def update_world(
    world_id: str,
    world_update: WorldUpdate,
    current_user: dict = Depends(get_current_active_user)
):
    """更新世界观信息"""
    if world_id not in worlds_db:
        raise HTTPException(status_code=404, detail="世界观不存在")
    world = worlds_db[world_id]
    if world["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权修改此世界观")

    update_data = world_update.model_dump(exclude_unset=True)
    world.update(update_data)
    world["updated_at"] = datetime.utcnow().isoformat()
    worlds_db[world_id] = world
    return {"message": "世界观信息更新成功"}

@app.delete("/api/worlds/{world_id}")
async def delete_world(world_id: str, current_user: dict = Depends(get_current_active_user)):
    """删除世界观"""
    if world_id not in worlds_db:
        raise HTTPException(status_code=404, detail="世界观不存在")
    world = worlds_db[world_id]
    if world["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权删除此世界观")

    del worlds_db[world_id]
    # 删除相关地点和事件
    locations_to_delete = [
        location_id for location_id, location in locations_db.items()
        if location["world_id"] == world_id
    ]
    for location_id in locations_to_delete:
        del locations_db[location_id]

    events_to_delete = [
        event_id for event_id, event in events_db.items()
        if event["world_id"] == world_id
    ]
    for event_id in events_to_delete:
        del events_db[event_id]

    return {"message": "世界观删除成功"}

@app.post("/api/worlds/{world_id}/locations")
async def create_location(
    world_id: str,
    location: LocationCreate,
    current_user: dict = Depends(get_current_active_user)
):
    """添加地点"""
    if world_id not in worlds_db:
        raise HTTPException(status_code=404, detail="世界观不存在")
    world = worlds_db[world_id]
    if world["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权在此世界观中添加地点")

    location_id = f"{world_id}_location_{len(locations_db) + 1}"
    location_data = location.model_dump()
    location_data.update({
        "id": location_id,
        "world_id": world_id,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    })
    locations_db[location_id] = location_data
    return location_data

@app.get("/api/worlds/{world_id}/locations")
async def list_locations(world_id: str, current_user: dict = Depends(get_current_active_user)):
    """获取世界观的地点列表"""
    if world_id not in worlds_db:
        raise HTTPException(status_code=404, detail="世界观不存在")
    world = worlds_db[world_id]
    if world["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权访问此世界观的地点")

    world_locations = [
        location for location in locations_db.values()
        if location["world_id"] == world_id
    ]
    return world_locations

@app.post("/api/worlds/{world_id}/events")
async def create_event(
    world_id: str,
    event: EventCreate,
    current_user: dict = Depends(get_current_active_user)
):
    """添加事件"""
    if world_id not in worlds_db:
        raise HTTPException(status_code=404, detail="世界观不存在")
    world = worlds_db[world_id]
    if world["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权在此世界观中添加事件")

    event_id = f"{world_id}_event_{len(events_db) + 1}"
    event_data = event.model_dump()
    event_data.update({
        "id": event_id,
        "world_id": world_id,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    })
    events_db[event_id] = event_data
    return event_data

# 角色相关路由
@app.post("/api/characters")
async def create_character(character: CharacterCreate, current_user: dict = Depends(get_current_active_user)):
    """创建新角色"""
    character_id = str(len(characters_db) + 1)
    character_data = character.model_dump()
    character_data.update({
        "id": character_id,
        "author_id": current_user["username"],
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    })
    characters_db[character_id] = character_data
    return character_data

@app.get("/api/characters/{character_id}")
async def get_character(character_id: str, current_user: dict = Depends(get_current_active_user)):
    """获取角色详情"""
    if character_id not in characters_db:
        raise HTTPException(status_code=404, detail="角色不存在")
    character = characters_db[character_id]
    if character["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权访问此角色")
    return character

@app.put("/api/characters/{character_id}")
async def update_character(
    character_id: str,
    character_update: CharacterUpdate,
    current_user: dict = Depends(get_current_active_user)
):
    """更新角色信息"""
    if character_id not in characters_db:
        raise HTTPException(status_code=404, detail="角色不存在")
    character = characters_db[character_id]
    if character["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权修改此角色")

    update_data = character_update.model_dump(exclude_unset=True)
    character.update(update_data)
    character["updated_at"] = datetime.utcnow().isoformat()
    characters_db[character_id] = character
    return {"message": "角色信息更新成功"}

@app.delete("/api/characters/{character_id}")
async def delete_character(character_id: str, current_user: dict = Depends(get_current_active_user)):
    """删除角色"""
    if character_id not in characters_db:
        raise HTTPException(status_code=404, detail="角色不存在")
    character = characters_db[character_id]
    if character["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权删除此角色")

    del characters_db[character_id]
    # 删除相关关系和对话
    relationships_to_delete = [
        rel_id for rel_id, rel in relationships_db.items()
        if rel["source_character_id"] == character_id or rel["target_character_id"] == character_id
    ]
    for rel_id in relationships_to_delete:
        del relationships_db[rel_id]

    dialogues_to_delete = [
        dialogue_id for dialogue_id, dialogue in dialogues_db.items()
        if dialogue["character_id"] == character_id
    ]
    for dialogue_id in dialogues_to_delete:
        del dialogues_db[dialogue_id]

    return {"message": "角色删除成功"}

@app.post("/api/characters/{character_id}/relationships")
async def create_relationship(
    character_id: str,
    relationship: RelationshipCreate,
    current_user: dict = Depends(get_current_active_user)
):
    """添加角色关系"""
    if character_id not in characters_db:
        raise HTTPException(status_code=404, detail="源角色不存在")
    source_character = characters_db[character_id]
    if source_character["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权为此角色添加关系")

    target_id = relationship.target_character_id
    if target_id not in characters_db:
        raise HTTPException(status_code=404, detail="目标角色不存在")

    relationship_id = f"{character_id}_rel_{len(relationships_db) + 1}"
    relationship_data = relationship.model_dump()
    relationship_data.update({
        "id": relationship_id,
        "source_character_id": character_id,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    })
    relationships_db[relationship_id] = relationship_data
    return relationship_data

@app.get("/api/characters/{character_id}/relationships")
async def list_relationships(character_id: str, current_user: dict = Depends(get_current_active_user)):
    """获取角色关系列表"""
    if character_id not in characters_db:
        raise HTTPException(status_code=404, detail="角色不存在")
    character = characters_db[character_id]
    if character["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权访问此角色的关系")

    character_relationships = [
        rel for rel in relationships_db.values()
        if rel["source_character_id"] == character_id
    ]
    return character_relationships

@app.post("/api/characters/{character_id}/dialogues")
async def create_dialogue(
    character_id: str,
    dialogue: DialogueCreate,
    current_user: dict = Depends(get_current_active_user)
):
    """添加角色对话"""
    if character_id not in characters_db:
        raise HTTPException(status_code=404, detail="角色不存在")
    character = characters_db[character_id]
    if character["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权为此角色添加对话")

    dialogue_id = f"{character_id}_dialogue_{len(dialogues_db) + 1}"
    dialogue_data = dialogue.model_dump()
    dialogue_data.update({
        "id": dialogue_id,
        "character_id": character_id,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    })
    dialogues_db[dialogue_id] = dialogue_data
    return dialogue_data

# 知识库相关路由
@app.post("/api/knowledge_bases")
async def create_knowledge_base(kb: KnowledgeBaseCreate, current_user: dict = Depends(get_current_active_user)):
    """创建新知识库"""
    kb_id = str(len(knowledge_bases_db) + 1)
    kb_data = kb.model_dump()
    kb_data.update({
        "id": kb_id,
        "author_id": current_user["username"],
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    })
    knowledge_bases_db[kb_id] = kb_data
    return kb_data

@app.get("/api/knowledge_bases/{kb_id}")
async def get_knowledge_base(kb_id: str, current_user: dict = Depends(get_current_active_user)):
    """获取知识库详情"""
    if kb_id not in knowledge_bases_db:
        raise HTTPException(status_code=404, detail="知识库不存在")
    kb = knowledge_bases_db[kb_id]
    if kb["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权访问此知识库")
    return kb

@app.put("/api/knowledge_bases/{kb_id}")
async def update_knowledge_base(
    kb_id: str,
    kb_update: KnowledgeBaseUpdate,
    current_user: dict = Depends(get_current_active_user)
):
    """更新知识库信息"""
    if kb_id not in knowledge_bases_db:
        raise HTTPException(status_code=404, detail="知识库不存在")
    kb = knowledge_bases_db[kb_id]
    if kb["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权修改此知识库")

    update_data = kb_update.model_dump(exclude_unset=True)
    kb.update(update_data)
    kb["updated_at"] = datetime.utcnow().isoformat()
    knowledge_bases_db[kb_id] = kb
    return {"message": "知识库信息更新成功"}

@app.delete("/api/knowledge_bases/{kb_id}")
async def delete_knowledge_base(kb_id: str, current_user: dict = Depends(get_current_active_user)):
    """删除知识库"""
    if kb_id not in knowledge_bases_db:
        raise HTTPException(status_code=404, detail="知识库不存在")
    kb = knowledge_bases_db[kb_id]
    if kb["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权删除此知识库")

    del knowledge_bases_db[kb_id]
    # 删除相关知识条目
    entries_to_delete = [
        entry_id for entry_id, entry in knowledge_entries_db.items()
        if entry["kb_id"] == kb_id
    ]
    for entry_id in entries_to_delete:
        del knowledge_entries_db[entry_id]

    return {"message": "知识库删除成功"}

@app.post("/api/knowledge_bases/{kb_id}/entries")
async def create_knowledge_entry(
    kb_id: str,
    entry: KnowledgeEntryCreate,
    current_user: dict = Depends(get_current_active_user)
):
    """添加知识条目"""
    if kb_id not in knowledge_bases_db:
        raise HTTPException(status_code=404, detail="知识库不存在")
    kb = knowledge_bases_db[kb_id]
    if kb["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权在此知识库中添加条目")

    entry_id = f"{kb_id}_entry_{len(knowledge_entries_db) + 1}"
    entry_data = entry.model_dump()
    entry_data.update({
        "id": entry_id,
        "kb_id": kb_id,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    })
    knowledge_entries_db[entry_id] = entry_data
    return entry_data

@app.get("/api/knowledge_bases/{kb_id}/entries")
async def list_knowledge_entries(kb_id: str, current_user: dict = Depends(get_current_active_user)):
    """获取知识库的条目列表"""
    if kb_id not in knowledge_bases_db:
        raise HTTPException(status_code=404, detail="知识库不存在")
    kb = knowledge_bases_db[kb_id]
    if kb["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权访问此知识库的条目")

    kb_entries = [
        entry for entry in knowledge_entries_db.values()
        if entry["kb_id"] == kb_id
    ]
    return kb_entries

@app.delete("/api/knowledge_bases/{kb_id}/entries/{entry_id}")
async def delete_knowledge_entry(
    kb_id: str,
    entry_id: str,
    current_user: dict = Depends(get_current_active_user)
):
    """删除知识条目"""
    if kb_id not in knowledge_bases_db:
        raise HTTPException(status_code=404, detail="知识库不存在")
    if entry_id not in knowledge_entries_db:
        raise HTTPException(status_code=404, detail="知识条目不存在")

    kb = knowledge_bases_db[kb_id]
    entry = knowledge_entries_db[entry_id]

    if kb["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权删除此知识条目")
    if entry["kb_id"] != kb_id:
        raise HTTPException(status_code=400, detail="知识条目不属于此知识库")

    del knowledge_entries_db[entry_id]
    return {"message": "知识条目删除成功"}

@app.post("/api/knowledge_bases/{kb_id}/search")
async def search_knowledge(
    kb_id: str,
    search_params: KnowledgeSearch,
    current_user: dict = Depends(get_current_active_user)
):
    """搜索知识库"""
    if kb_id not in knowledge_bases_db:
        raise HTTPException(status_code=404, detail="知识库不存在")
    kb = knowledge_bases_db[kb_id]
    if kb["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权搜索此知识库")

    # 简单实现：基于关键词匹配
    query = search_params.query.lower()
    limit = search_params.limit

    results = []
    for entry in knowledge_entries_db.values():
        if entry["kb_id"] != kb_id:
            continue

        score = 0
        # 标题匹配
        if query in entry["title"].lower():
            score += 3
        # 内容匹配
        if query in entry["content"].lower():
            score += 1
        # 标签匹配
        if entry.get("tags"):
            for tag in entry["tags"]:
                if query in tag.lower():
                    score += 2

        if score > 0:
            results.append({
                "entry": entry,
                "score": score
            })

    # 按相关性排序
    results.sort(key=lambda x: x["score"], reverse=True)

    # 限制结果数量
    results = results[:limit]

    return {"results": [r["entry"] for r in results]}

@app.post("/api/knowledge_bases/{kb_id}/recommend")
async def recommend_knowledge(
    kb_id: str,
    recommend_params: KnowledgeRecommend,
    current_user: dict = Depends(get_current_active_user)
):
    """基于上下文推荐知识"""
    if kb_id not in knowledge_bases_db:
        raise HTTPException(status_code=404, detail="知识库不存在")
    kb = knowledge_bases_db[kb_id]
    if kb["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权使用此知识库的推荐功能")

    # 简单实现：提取上下文中的关键词并匹配
    context = recommend_params.context.lower()
    limit = recommend_params.limit

    # 提取关键词（简化版）
    words = context.split()
    keywords = [word for word in words if len(word) > 3]  # 简单过滤短词

    results = []
    for entry in knowledge_entries_db.values():
        if entry["kb_id"] != kb_id:
            continue

        score = 0
        entry_text = (entry["title"] + " " + entry["content"]).lower()

        # 关键词匹配
        for keyword in keywords:
            if keyword in entry_text:
                score += 1

        if score > 0:
            results.append({
                "entry": entry,
                "score": score
            })

    # 按相关性排序
    results.sort(key=lambda x: x["score"], reverse=True)

    # 限制结果数量
    results = results[:limit]

    return {"recommendations": [r["entry"] for r in results]}

# 文件上传下载路由
@app.post("/api/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    type: str = Form(...),
    description: Optional[str] = Form(None),
    current_user: dict = Depends(get_current_active_user)
):
    """上传文件"""
    # 生成唯一文件ID
    file_id = str(uuid.uuid4())

    # 获取文件信息
    filename = file.filename
    content_type = file.content_type

    # 创建用户目录
    user_dir = os.path.join(UPLOAD_DIR, current_user["username"])
    os.makedirs(user_dir, exist_ok=True)

    # 保存文件
    file_path = os.path.join(user_dir, file_id + "_" + filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 获取文件大小
    file_size = os.path.getsize(file_path)

    # 保存文件信息到数据库
    file_info = {
        "file_id": file_id,
        "filename": filename,
        "type": type,
        "description": description,
        "content_type": content_type,
        "size": file_size,
        "path": file_path,
        "author_id": current_user["username"],
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }
    files_db[file_id] = file_info

    return {"file_id": file_id, "filename": filename, "size": file_size}

@app.get("/api/files/{file_id}/info")
async def get_file_info(file_id: str, current_user: dict = Depends(get_current_active_user)):
    """获取文件信息"""
    if file_id not in files_db:
        raise HTTPException(status_code=404, detail="文件不存在")

    file_info = files_db[file_id]
    if file_info["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权访问此文件")

    # 返回文件信息（排除内部路径）
    return {k: v for k, v in file_info.items() if k != "path"}

@app.get("/api/files/{file_id}/download")
async def download_file(file_id: str, current_user: dict = Depends(get_current_active_user)):
    """下载文件"""
    if file_id not in files_db:
        raise HTTPException(status_code=404, detail="文件不存在")

    file_info = files_db[file_id]
    if file_info["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权下载此文件")

    file_path = file_info["path"]
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="文件已被删除")

    return FileResponse(
        path=file_path,
        filename=file_info["filename"],
        media_type=file_info["content_type"]
    )

@app.delete("/api/files/{file_id}")
async def delete_file(file_id: str, current_user: dict = Depends(get_current_active_user)):
    """删除文件"""
    if file_id not in files_db:
        raise HTTPException(status_code=404, detail="文件不存在")

    file_info = files_db[file_id]
    if file_info["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="无权删除此文件")

    file_path = file_info["path"]

    # 删除文件
    if os.path.exists(file_path):
        os.remove(file_path)

    # 从数据库中删除文件信息
    del files_db[file_id]

    return {"message": "文件删除成功"}

# 调试路由
@app.get("/api/debug/routes")
async def get_routes():
    """获取所有路由信息（调试用）"""
    routes = []
    for route in app.routes:
        routes.append({
            "path": route.path,
            "name": route.name,
            "methods": route.methods
        })
    return {"routes": routes}

@app.get("/api/debug/users")
async def get_users():
    """获取所有用户信息（调试用）"""
    return {"users": users_db}

@app.get("/api/debug/novels")
async def get_novels():
    """获取所有小说信息（调试用）"""
    return {"novels": novels_db}

@app.get("/api/debug/chapters")
async def get_chapters():
    """获取所有章节信息（调试用）"""
    return {"chapters": chapters_db}

if __name__ == "__main__":
    # 添加测试用户
    test_user = UserCreate(
        username="testuser",
        password="testpass",
        email="test@example.com"
    )
    if test_user.username not in users_db:
        hashed_password = get_password_hash(test_user.password)
        users_db[test_user.username] = {
            "username": test_user.username,
            "password": hashed_password,
            "email": test_user.email,
            "disabled": False
        }

    # 启动服务器
    uvicorn.run(
        app,
        host="127.0.0.1",  # 使用本地回环地址
        port=8081,  # 使用不同的端口
        log_level="debug",
        access_log=True
    )
