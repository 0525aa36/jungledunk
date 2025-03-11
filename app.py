from flask import Flask, request, jsonify, render_template
import jwt
import os
from datetime import datetime, timedelta
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # 24바이트의 랜덤한 값 생성

# MongoDB 연결 (MongoDB 서버가 로컬에서 실행 중이어야 함)
client = MongoClient('mongodb://localhost:27017/')
db = client['user_database']
users_collection = db['users']
# app.py 상단에 추가
matches_collection = db['matches']


# 메인 페이지 (index.html) - 로그인 상태에 따라 버튼이 변경됨
@app.route('/')
def index():
    return render_template('index.html')

# 회원가입 페이지 (register.html)
@app.route('/register', methods=['GET'])
def show_register_page():
    return render_template('register.html')

# 로그인 페이지 (login.html)
@app.route('/login', methods=['GET'])
def show_login_page():
    return render_template('login.html')

@app.route('/recruitment' , methods=['GET'])
def recruitment():
    return render_template('recruitment.html')


# 회원가입 API (POST)
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # 모든 필드 입력 여부 확인
    if not all(k in data for k in ['username', 'password', 'phone', 'email']):
        return jsonify({'message': '모든 필드를 입력하세요!'}), 400

    username = data['username']
    password = data['password']
    phone = data['phone']
    email = data['email']
    created_at = datetime.datetime.utcnow()

    # 중복 검사 (username, email, phone)
    if users_collection.find_one({'username': username}):
        return jsonify({'message': '이미 존재하는 사용자 이름입니다!'}), 400
    if users_collection.find_one({'email': email}):
        return jsonify({'message': '이미 존재하는 이메일입니다!'}), 400
    if users_collection.find_one({'phone': phone}):
        return jsonify({'message': '이미 존재하는 전화번호입니다!'}), 400

    # 비밀번호 암호화
    hashed_password = generate_password_hash(password)

    # 사용자 정보 저장
    users_collection.insert_one({
        'username': username,
        'password': hashed_password,
        'phone': phone,
        'email': email,
        'created_at': created_at
    })

    # 회원가입 성공 후 자동 로그인 (JWT 토큰 생성)
    payload = {
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'message': '회원가입 성공!', 'token': token}), 201

# 로그인 API (POST)
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if 'email' not in data or 'password' not in data:
        return jsonify({'message': '이메일과 비밀번호를 입력하세요!'}), 400

    email = data['email']
    password = data['password']

    # DB에서 email로 사용자 찾기
    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'message': '이메일 또는 비밀번호가 올바르지 않습니다!'}), 401

    # 비밀번호 확인
    if not check_password_hash(user['password'], password):
        return jsonify({'message': '이메일 또는 비밀번호가 올바르지 않습니다!'}), 401

    # 로그인 성공 시 JWT 토큰 생성
    # 여기서 'username'을 payload에 담아준다.
    payload = {
    'username': user['username'],
    'exp': datetime.utcnow() + timedelta(hours=1)
}
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'message': '로그인 성공!', 'token': token}), 200

def parse_time(time_str):
    return datetime.strptime(time_str, "%H:%M")

@app.route('/create_match', methods=['POST'])
def create_match():
    data = request.get_json()
    required_fields = ['creator_id', 'memo', 'date', 'time_start', 'time_end', 'court_type', 'max_players']
    if not all(field in data for field in required_fields):
        return jsonify({'message': '필수 필드를 모두 입력하세요.'}), 400

    new_date = data['date']
    new_time_start = parse_time(data['time_start'])
    new_time_end = parse_time(data['time_end'])
    new_court_type = data['court_type'].lower()  # "full" 또는 "half"

    # 같은 날짜에 모집중인 예약들을 조회
    existing_matches = list(matches_collection.find({'date': new_date, 'status': '모집중'}))
    
    if new_court_type == "full":
        # full 예약은 동일 날짜, 동일 시간에 full 예약이 있으면 안됨
        for match in existing_matches:
            if match['court_type'].lower() == "full":
                existing_start = parse_time(match["time_start"])
                existing_end = parse_time(match["time_end"])
                if new_time_start < existing_end and existing_start < new_time_end:
                    return jsonify({'message': '해당 시간대에는 이미 Full 코트 예약이 있습니다.'}), 400
    elif new_court_type == "half":
        # half 예약은 동일 날짜, 동일 시간에 half 예약이 2건 이상이면 안됨
        count = 0
        for match in existing_matches:
            if match['court_type'].lower() == "half":
                existing_start = parse_time(match["time_start"])
                existing_end = parse_time(match["time_end"])
                if new_time_start < existing_end and existing_start < new_time_end:
                    count += 1
        if count >= 2:
            return jsonify({'message': '해당 시간대에는 이미 2건의 Half 코트 예약이 있습니다.'}), 400

    # 검증 통과 시 새로운 모집 생성
    new_match = {
        'creator_id': data['creator_id'],
        'memo': data['memo'],
        'date': new_date,
        'time_start': data['time_start'],
        'time_end': data['time_end'],
        'court_type': data['court_type'],
        'max_players': int(data['max_players']),
        'current_players': 1,  # 생성 시 본인이 포함되므로
        'status': '모집중',
        'cancel_reason': '',
        'created_at': datetime.utcnow()
    }
    result = matches_collection.insert_one(new_match)
    return jsonify({'message': '모집 등록 성공!', 'match_id': str(result.inserted_id)}), 201

# app.py 에 추가
@app.route('/reserved_times')
def get_reserved_times():
    date = request.args.get('date')
    if not date:
        return jsonify({'message': '날짜를 입력하세요.'}), 400

    # 같은 날짜에 모집중인 예약들을 조회합니다.
    matches = list(matches_collection.find({'date': date, 'status': '모집중'}))
    # 예약된 시작 시간을 중복 없이 추출합니다.
    reserved_times = list({match['time_start'] for match in matches})
    return jsonify({'reserved': reserved_times}), 200


if __name__ == '__main__':
    app.run(debug=True)
