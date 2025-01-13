from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
from werkzeug.utils import secure_filename
from bson import ObjectId

app = Flask(__name__)
# 修改 CORS 配置，允许所有请求头和方法
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "allow_headers": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    }
})

# MongoDB配置
app.config["MONGO_URI"] = "mongodb://8.138.128.205:27017/Shop"
app.config['SECRET_KEY'] = 'zyh250520'  # 建议使用随机生成的密钥
mongo = PyMongo(app)

# 文件上传配置
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-limit

# 确保上传目录存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 添加静态文件访问路由
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# 登录
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = mongo.db.Users.find_one({'username': username})
    
    if user and check_password_hash(user['password'], password):
        token = jwt.encode({
            'user_id': str(user['_id']),
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }, app.config['SECRET_KEY'])
        
        return jsonify({
            'success': True,
            'token': token,
            'username': username,
            'is_admin': user.get('is_admin', False)
        })
    else:
        return jsonify({'success': False, 'message': '用户名或密码错误'})


#注册
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': '用户名和密码不能为空'})
    
    if mongo.db.Users.find_one({'username': username}):
        return jsonify({'success': False, 'message': '用户名已存在'})
    
    hashed_password = generate_password_hash(password, method='sha256')
    
    mongo.db.Users.insert_one({
        'username': username,
        'password': hashed_password,
        'created_at': datetime.datetime.utcnow()
    })
    
    return jsonify({'success': True, 'message': '注册成功'})



#个人中心-获取用户信息
@app.route('/api/user/info', methods=['GET'])
def get_user_info():
    try:
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        user = mongo.db.Users.find_one({'_id': ObjectId(user_id)})
        if user:
            return jsonify({
                'success': True,
                'userInfo': {
                    'username': user['username'],
                    'qq': user.get('qq', ''),
                    'wechat': user.get('wechat', ''),
                    'avatar': user.get('avatar', ''),
                    'signature': user.get('signature', '这个人很懒，什么都没写~'),
                    'background_image': user.get('background_image', ''),
                    'is_admin': user.get('is_admin', False)
                }
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


# 个人中心-更新用户信息
@app.route('/api/user/info', methods=['PUT'])
def update_user_info():
    try:
        # 验证用户身份
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        data = request.get_json()
        
        # 准备更新数据
        update_data = {
            'qq': data.get('qq', ''),
            'wechat': data.get('wechat', ''),
            'signature': data.get('signature', ''),
            'avatar': data.get('avatar', ''),
            'background_image': data.get('background_image', '')
        }
        
        # 如果要更改用户名，先检查是否存在
        if data.get('username') and data['username'] != payload['username']:
            existing_user = mongo.db.Users.find_one({'username': data['username']})
            if existing_user:
                return jsonify({
                    'success': False,
                    'message': '用户名已存在'
                }), 400
            update_data['username'] = data['username']
        
        # 更新用户信息
        mongo.db.Users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_data}
        )
        
        return jsonify({
            'success': True,
            'message': '更新成功'
        })
        
    except Exception as e:
        print(f"Error updating user info: {str(e)}")  # 添加错误日志
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

#上传图片
@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': '没有文件'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': '没有选择文件'})
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filename = f"{datetime.datetime.now().timestamp()}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        return jsonify({
            'success': True,
            'url': f"/uploads/{filename}"
        })
    
    return jsonify({'success': False, 'message': '不允许的文件类型'})



# 删除图片 
@app.route('/api/upload/<filename>', methods=['DELETE'])
def delete_upload(filename):
    try:
        # 打印调试信息
        print(f"Attempting to delete file: {filename}")
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        print(f"Full file path: {file_path}")
        
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"File successfully deleted: {filename}")
            return jsonify({
                'success': True,
                'message': '文件删除成功'
            })
        else:
            print(f"File not found: {filename}")
            return jsonify({
                'success': False,
                'message': '文件不存在'
            })
    except Exception as e:
        print(f"Error deleting file: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500
    

# 发布商品 
@app.route('/api/items', methods=['POST'])
def create_item():
    try:
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        username = payload['username']  # 从token中获取用户名
        
        data = request.get_json()
        item = {
            'title': data['title'],
            'price': float(data['price']),
            'category': data['category'],
            'images': data['images'],
            'description': data['description'],
            'qq': data['qq'],
            'wechat': data['wechat'],
            'userId': user_id,
            'username': username,  # 添加用户名字段
            'time': datetime.datetime.now(),
            'status': 'active'
        }
        
        result = mongo.db.items.insert_one(item)
        
        return jsonify({
            'success': True,
            'message': '发布成功',
            'itemId': str(result.inserted_id)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500



# 首页-获取商品列表
@app.route('/api/items', methods=['GET'])
def get_items():
    try:
        # 获取用户ID
        token = request.headers.get('Authorization', '').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        # 获取查询参数
        category = request.args.get('category')
        search = request.args.get('search')
        page = int(request.args.get('page', 1))
        per_page = 12

        # 构建查询条件
        query = {'status': 'active'}
        if category:
            query['category'] = category
        if search:
            search_regex = {'$regex': search, '$options': 'i'}
            query['$or'] = [
                {'title': search_regex},
                {'description': search_regex}
            ]

        # 获取用户的收藏列表
        favorites = set(str(fav['item_id']) for fav in mongo.db.favorite.find({'user_id': user_id}))
        
        # 执行查询
        total = mongo.db.items.count_documents(query)
        items = list(mongo.db.items.find(query)
                    .sort('time', -1)
                    .skip((page - 1) * per_page)
                    .limit(per_page))
        
        # 添加收藏状态
        for item in items:
            item['_id'] = str(item['_id'])
            item['isFavorite'] = item['_id'] in favorites
            if isinstance(item.get('time'), datetime.datetime):
                item['time'] = item['time'].isoformat()

        return jsonify({
            'success': True,
            'items': items,
            'total': total,
            'current_page': page
        })

    except Exception as e:
        print(f"Error in get_items: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'获取商品列表失败: {str(e)}'
        }), 500



# 首页或我的主页-获取某用户的商品列表
@app.route('/api/users/<username>/items', methods=['GET'])
def get_user_items(username):
    try:
        # 移除 status: 'active' 条件，返回所有状态的商品
        items = list(mongo.db.items.find({
            'username': username
        }).sort('time', -1))
        
        # 处理ObjectId和时间格式
        for item in items:
            item['_id'] = str(item['_id'])
            if isinstance(item.get('time'), datetime.datetime):
                item['time'] = item['time'].isoformat()
        
        return jsonify({
            'success': True,
            'items': items
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500



# 我的主页-删除商品(彻底删除)
@app.route('/api/items/<item_id>', methods=['DELETE'])
def delete_item(item_id):
    try:
        # 验证用户身份
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        # 获取商品信息以删除图片
        item = mongo.db.items.find_one({
            '_id': ObjectId(item_id),
            'userId': user_id
        })
        
        if not item:
            return jsonify({'success': False, 'message': '商品不存在或无权删除'}), 403
        
        # 删除商品关联的图片文件
        if item.get('images'):
            for image_url in item['images']:
                try:
                    filename = image_url.split('/')[-1]
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as e:
                    print(f"删除图片文件失败: {str(e)}")

        # 删除商品
        result = mongo.db.items.delete_one({
            '_id': ObjectId(item_id),
            'userId': user_id
        })
        
        if result.deleted_count == 0:
            return jsonify({'success': False, 'message': '商品不存在或无权删除'}), 403
        
        # 删除相关的收藏记录
        mongo.db.favorite.delete_many({'item_id': item_id})
        
        return jsonify({
            'success': True,
            'message': '商品删除成功'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# 我的主页-修改商品状态（下架）
@app.route('/api/items/<item_id>/status', methods=['PUT'])
def update_item_status(item_id):
    try:
        # 验证用户身份
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        # 查找商品并验证所有权
        item = mongo.db.items.find_one({
            '_id': ObjectId(item_id),
            'userId': user_id
        })
        
        if not item:
            return jsonify({
                'success': False,
                'message': '商品不存在或无权操作'
            }), 403
        
        # 更新商品状态为 inactive 下架
        mongo.db.items.update_one(
            {'_id': ObjectId(item_id)},
            {'$set': {'status': 'inactive'}}
        )
        
        return jsonify({
            'success': True,
            'message': '商品已下架'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500



# 获取指定用户的信息
@app.route('/api/users/<username>/info', methods=['GET'])
def get_user_profile(username):
    try:
        user = mongo.db.Users.find_one({'username': username})
        if user:
            return jsonify({
                'success': True,
                'userInfo': {
                    'username': user['username'],
                    'avatar': user.get('avatar', ''),
                    'signature': user.get('signature', '这个人很懒，什么都没写~'),
                    'qq': user.get('qq', ''),  # 添加 QQ
                    'wechat': user.get('wechat', ''),  # 添加微信
                    'background_image': user.get('background_image', '')  # 添加背景图片
                }
            })
        return jsonify({
            'success': False,
            'message': '用户不存在'
        }), 404
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500



# 编辑商品
@app.route('/api/items/<item_id>', methods=['PUT'])
def update_item(item_id):
    try:
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        # 查找商品并验证所有权
        item = mongo.db.items.find_one({
            '_id': ObjectId(item_id),
            'userId': user_id
        })
        
        if not item:
            return jsonify({
                'success': False,
                'message': '商品不存在或无权修改'
            }), 403
        
        data = request.get_json()
        update_data = {
            'title': data['title'],
            'price': float(data['price']),
            'category': data['category'],
            'description': data['description'],
            'qq': data['qq'],
            'wechat': data['wechat']
        }
        
        mongo.db.items.update_one(
            {'_id': ObjectId(item_id)},
            {'$set': update_data}
        )
        
        return jsonify({
            'success': True,
            'message': '更新成功'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# 添加收藏
@app.route('/api/favorites', methods=['POST'])
def add_favorite():
    try:
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        data = request.get_json()
        item_id = data.get('item_id')
        
        # 检查是否已经收藏
        existing = mongo.db.favorite.find_one({
            'user_id': user_id,
            'item_id': item_id
        })
        
        if existing:
            # 如果已收藏，则取消收藏
            mongo.db.favorite.delete_one({
                'user_id': user_id,
                'item_id': item_id
            })
            return jsonify({
                'success': True,
                'message': '取消收藏成功',
                'isFavorite': False
            })
        else:
            # 添加收藏
            mongo.db.favorite.insert_one({
                'user_id': user_id,
                'item_id': item_id,
                'time': datetime.datetime.utcnow()
            })
            return jsonify({
                'success': True,
                'message': '收藏成功',
                'isFavorite': True
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# 获取用户收藏列表
@app.route('/api/favorites', methods=['GET'])
def get_favorites():
    try:
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        # 获取用户的所有收藏
        favorites = list(mongo.db.favorite.find({'user_id': user_id}))
        
        # 获取收藏的商品详情
        favorite_items = []
        for fav in favorites:
            item = mongo.db.items.find_one({'_id': ObjectId(fav['item_id'])})
            if item and item.get('status') == 'active':
                item['_id'] = str(item['_id'])
                if isinstance(item.get('time'), datetime.datetime):
                    item['time'] = item['time'].isoformat()
                favorite_items.append(item)
        
        return jsonify({
            'success': True,
            'items': favorite_items
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


# 添加更新背景图片的接口
@app.route('/api/user/background', methods=['PUT'])
def update_background():
    try:
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': '没有文件'})
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': '没有选择文件'})
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename = f"{datetime.datetime.now().timestamp()}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            file_url = f'http://localhost:5000/uploads/{filename}'
            
            # 更新用户背景图片
            mongo.db.Users.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'background_image': file_url}}
            )
            
            return jsonify({
                'success': True,
                'message': '背景图片更新成功',
                'background_image': file_url
            })
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# 管理员获取所有用户信息
@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    try:
        # 验证是否是管理员
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload.get('username')
        
        # 只允许 admin 用户访问
        if username != 'admin':
            return jsonify({'success': False, 'message': '无权限'}), 403
        
        # 获取所有用户信息，排除密码字段
        users = list(mongo.db.Users.find({}, {'password': 0}))
        
        # 转换 ObjectId 为字符串
        for user in users:
            user['_id'] = str(user['_id'])
        
        return jsonify({
            'success': True,
            'users': users
        })
    except Exception as e:
        print(f"管理员获取所有用户信息失败: {str(e)}")  # 添加错误日志
        return jsonify({'success': False, 'message': str(e)}), 500

# 管理员获取所有商品列表
@app.route('/api/admin/items', methods=['GET'])
def get_all_items():
    try:
        # 验证是否是管理员
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload.get('username')
        
        if username != 'admin':
            return jsonify({'success': False, 'message': '无权限'}), 403
        
        # 获取分页和搜索参数
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 12))
        search = request.args.get('search', '').strip()
        
        # 构建查询条件
        query = {}
        if search:
            # 使用正则表达式进行模糊匹配
            search_regex = {'$regex': search, '$options': 'i'}
            query['$or'] = [
                {'title': search_regex},  # 匹配商品名
                {'username': search_regex}  # 匹配发布者名
            ]
        
        # 获取总数
        total = mongo.db.items.count_documents(query)
        
        # 获取分页数据
        items = list(mongo.db.items.find(query)
                    .sort('time', -1)
                    .skip((page - 1) * per_page)
                    .limit(per_page))
        
        # 处理数据
        for item in items:
            item['_id'] = str(item['_id'])
            
        return jsonify({
            'success': True,
            'items': items,
            'total': total
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# 管理员修改用户权限
@app.route('/api/admin/users/<user_id>/role', methods=['PUT'])
def update_user_role(user_id):
    try:
        # 验证是否是管理员
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload.get('username')
        
        if username != 'admin':
            return jsonify({'success': False, 'message': '无权限'}), 403
        
        data = request.get_json()
        is_admin = data.get('is_admin', False)
        
        # 更新用户权限
        mongo.db.Users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'is_admin': is_admin}}
        )
        
        return jsonify({
            'success': True,
            'message': '权限更新成功'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# 管理员删除用户
@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    try:
        # 验证是否是管理员
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload.get('username')
        
        if username != 'admin':
            return jsonify({'success': False, 'message': '无权限'}), 403
        
        
        # 删除用户及其相关数据
        mongo.db.Users.delete_one({'_id': ObjectId(user_id)})
        mongo.db.items.delete_many({'userId': user_id})
        
        return jsonify({
            'success': True,
            'message': '用户删除成功'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# 管理员删除商品
@app.route('/api/admin/items/<item_id>', methods=['DELETE'])
def admin_delete_item(item_id):
    try:
        # 验证是否是管理员
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload.get('username')
        
        if username != 'admin':
            return jsonify({'success': False, 'message': '无权限'}), 403
        
        # 获取商品信息以删除图片
        item = mongo.db.items.find_one({'_id': ObjectId(item_id)})
        if item and item.get('images'):
            for image_url in item['images']:
                try:
                    filename = image_url.split('/')[-1]
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as e:
                    print(f"删除图片文件失败: {str(e)}")

        # 删除商品
        mongo.db.items.delete_one({'_id': ObjectId(item_id)})
        # 删除相关的收藏记录
        mongo.db.favorite.delete_many({'item_id': item_id})
        
        return jsonify({
            'success': True,
            'message': '商品删除成功'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# 管理员下架商品
@app.route('/api/admin/items/<item_id>/status', methods=['PUT'])
def admin_update_item_status(item_id):
    try:
        # 验证是否是管理员
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload.get('username')
        
        if username != 'admin':
            return jsonify({'success': False, 'message': '无权限'}), 403
        
        
        # 更新商品状态
        mongo.db.items.update_one(
            {'_id': ObjectId(item_id)},
            {'$set': {'status': 'inactive'}}
        )
        
        return jsonify({
            'success': True,
            'message': '商品已下架'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# 管理员重新上架商品
@app.route('/api/admin/items/<item_id>/activate', methods=['PUT'])
def activate_item(item_id):
    try:
        # 验证是否是管理员
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload.get('username')
        
        if username != 'admin':
            return jsonify({'success': False, 'message': '无权限'}), 403
        
        
        # 更新商品状态
        mongo.db.items.update_one(
            {'_id': ObjectId(item_id)},
            {'$set': {'status': 'active'}}
        )
        
        return jsonify({
            'success': True,
            'message': '商品已重新上架'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# 管理员发送消息
@app.route('/api/admin/messages', methods=['POST'])
def send_message():
    try:
        # 验证是否是管理员
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload.get('username')
        
        if username != 'admin':
            return jsonify({'success': False, 'message': '无权限'}), 403
        
        data = request.get_json()
        message = {
            'content': data.get('content'),
            'recipients': data.get('recipients', []),  # 为空数组表示发送给所有用户
            'time': datetime.datetime.now(),
            'read_by': []  # 记录已读用户
        }
        
        # 插入消息
        mongo.db.messages.insert_one(message)
        
        return jsonify({
            'success': True,
            'message': '消息发送成功'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# 普通用户获取管理员消息
@app.route('/api/messages', methods=['GET'])
def get_messages():
    try:
        # 验证用户身份
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload.get('username')  # 使用用户名
        
        # 查询发给该用户或所有用户的消息
        messages = list(mongo.db.messages.find({
            '$or': [
                {'recipients': []},  # 发给所有用户的消息
                {'recipients': username}  # 发给特定用户的消息
            ]
        }).sort('time', -1))
        
        # 处理数据格式并计算未读状态
        for msg in messages:
            msg['_id'] = str(msg['_id'])
            if isinstance(msg.get('time'), datetime.datetime):
                msg['time'] = msg['time'].isoformat()
            # 检查用户名是否在已读列表中
            read_by = msg.get('read_by', [])
            msg['is_read'] = username in read_by
        
        # 只计算真正未读的消息数量
        unread_count = len([msg for msg in messages if not msg['is_read']])
        
        return jsonify({
            'success': True,
            'messages': messages,
            'unread_count': unread_count
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# 添加标记消息为已读的接口
@app.route('/api/messages/read', methods=['POST'])
def mark_messages_read():
    try:
        # 验证用户身份
        token = request.headers.get('Authorization').split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload.get('username')  # 使用用户名
        
        data = request.get_json()
        message_ids = data.get('message_ids', [])
        
        # 将消息标记为已读
        for msg_id in message_ids:
            mongo.db.messages.update_one(
                {'_id': ObjectId(msg_id)},
                {'$addToSet': {'read_by': username}}  # 添加用户名到已读列表
            )
        
        return jsonify({
            'success': True,
            'message': '消息已标记为已读'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 