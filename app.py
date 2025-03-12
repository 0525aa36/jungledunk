from flask import Flask, request, jsonify, render_template, redirect, url_for
import jwt
import os
from datetime import datetime, timedelta
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message 

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # 24바이트의 랜덤한 값 생성

# MongoDB 연결 (MongoDB 서버가 로컬에서 실행 중이어야 함)
client = MongoClient('mongodb://localhost:27017/')
db = client['user_database']
users_collection = db['users'] 
matches_collection = db['matches']
reservations_collection = db['reservations']

# Flask-Mail 설정 (SMTP 서버 정보는 실제 환경에 맞게 조정)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'jungle.dunkk@gmail.com'
app.config['MAIL_PASSWORD'] = 'wowow131'
app.config['MAIL_DEFAULT_SENDER'] = 'jungle.dunkk@gmail.com'
app.config['MAIL_SUPPRESS_SEND'] = False  # True로 설정하면 실제 전송 안함
mail = Mail(app)

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

@app.route('/comment' , methods=['GET'])
def comment():
    return render_template('comment.html')

@app.route('/reservations' , methods=['GET'])
def reservations():
    return render_template('reservations.html')

# 회원가입 API (POST)
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # 필수 필드 확인
    if not data or 'username' not in data or 'password' not in data or 'email' not in data:
        return jsonify({'message': '모든 필드를 입력하세요!'}), 400

    # 중복된 이메일이 있는지 확인
    existing_user = users_collection.find_one({'email': data['email']})
    if existing_user:
        return jsonify({'message': '이미 존재하는 이메일입니다.'}), 400

    # 비밀번호 해싱
    hashed_password = generate_password_hash(data['password'])

    # 사용자 데이터 저장
    new_user = {
        'username': data['username'],
        'email': data['email'],
        'password': hashed_password,
        'created_at': datetime.utcnow()
    }
    result = users_collection.insert_one(new_user)

    # **ObjectId를 문자열로 변환하여 JWT 생성**
    payload = {
        'username': new_user['username'],
        'user_id': str(result.inserted_id),  # ✅ user_id를 문자열로 변환
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'message': '회원가입 성공!', 'token': token}), 201


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

    # 로그인 성공 시 JWT 토큰 생성 (사용자의 _id도 포함)
    payload = {
    'username': user['username'],
    'user_id': str(user['_id']),  # ✅ ObjectId를 문자열로 변환
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
    new_court_type = data['court_type'].lower()

    existing_matches = list(matches_collection.find({'date': new_date, 'status': '모집중'}))
    if new_court_type == "full":
        for match in existing_matches:
            if match['court_type'].lower() == "full":
                existing_start = parse_time(match["time_start"])
                existing_end = parse_time(match["time_end"])
                if new_time_start < existing_end and existing_start < new_time_end:
                    return jsonify({'message': '해당 시간대에는 이미 Full 코트 예약이 있습니다.'}), 400
    elif new_court_type == "half":
        count = 0
        for match in existing_matches:
            if match['court_type'].lower() == "half":
                existing_start = parse_time(match["time_start"])
                existing_end = parse_time(match["time_end"])
                if new_time_start < existing_end and existing_start < new_time_end:
                    count += 1
        if count >= 2:
            return jsonify({'message': '해당 시간대에는 이미 2건의 Half 코트 예약이 있습니다.'}), 400

    new_match = {
        '_id': ObjectId(),
        'creator_id': str(data['creator_id']),  # creator_id를 문자열로 저장
        'memo': data['memo'],
        'date': data['date'],
        'time_start': data['time_start'],
        'time_end': data['time_end'],
        'court_type': data['court_type'],
        'max_players': int(data['max_players']),
        'current_players': 1,
        'status': '모집중',
        'cancel_reason': '',
        'created_at': datetime.utcnow()
    }

    matches_collection.insert_one(new_match)

    # 매치 생성자도 예약에 자동 포함
    reservation = {
        'match_id': new_match['_id'],
        'user_id': new_match['creator_id'],
        'reserved_at': datetime.utcnow()
    }
    reservations_collection.insert_one(reservation)

    return jsonify({'message': '모집 등록 성공!', 'match_id': str(new_match['_id'])}), 201



@app.route('/get_matches', methods=['GET'])
def get_matches():
    date = request.args.get('date')
    if not date:
        return jsonify({'message': '날짜를 입력하세요.'}), 400

    matches = list(matches_collection.find({'date': date, 'status': '모집중'}))
    matches_data = []
    
    for match in matches:
        creator_name = "알 수 없음"
        creator_id = match.get('creator_id')
        
        # creator_id가 유효한 ObjectId 문자열이면 사용자 조회
        if ObjectId.is_valid(creator_id):
            creator = users_collection.find_one({'_id': ObjectId(creator_id)})
            if creator:
                creator_name = creator['username']
        
        matches_data.append({
            'match_id': str(match['_id']),
            'memo': match.get('memo', ''),
            'date': match.get('date', ''),
            'time_start': match.get('time_start', ''),
            'time_end': match.get('time_end', ''),
            'court_type': match.get('court_type', ''),
            'current_players': match.get('current_players', 0),
            'max_players': match.get('max_players', 0),
            'creator_id': creator_id,  # 그대로 문자열로 반환
            'creator_name': creator_name
        })
    
    return jsonify({'matches': matches_data}), 200







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

@app.route('/create_reservation', methods=['POST'])
def create_reservation():
    data = request.get_json()

    # 필수 필드 확인
    if not all(k in data for k in ['match_id', 'user_id']):
        return jsonify({'message': '필수 필드를 입력하세요.'}), 400

    match_id = str(data['match_id'])  # match_id를 문자열로 변환
    user_id = data['user_id']

    print(f"🔍 받은 match_id: {match_id} (타입: {type(match_id)})")

    # match_id가 유효한 ObjectId인지 검증
    try:
        match_obj_id = ObjectId(match_id)
    except Exception as e:
        print(f"❌ match_id 변환 오류: {e}")
        return jsonify({'message': '잘못된 match_id입니다.'}), 400

    # 예약 정보 저장
    reservations_collection = db['reservations']
    reservation = {
        'match_id': match_obj_id,  # ObjectId 사용
        'user_id': user_id,
        'reserved_at': datetime.utcnow()
    }
    reservations_collection.insert_one(reservation)

    # 해당 매치의 current_players 1 증가
    matches_collection.update_one(
        {'_id': match_obj_id},  # ObjectId 사용
        {'$inc': {'current_players': 1}}
    )

    return jsonify({'message': '예약 신청이 완료되었습니다!'}), 201


@app.route('/add_comment', methods=['POST'])
def add_comment():
    data = request.get_json()
    # 필수 필드: match_id, user_id, content
    if not all(k in data for k in ['match_id', 'user_id', 'content']):
        return jsonify({'message': '필수 필드를 입력하세요.'}), 400

    comment = {
        'match_id': data['match_id'],
        'user_id': data['user_id'],
        'content': data['content'],
        'created_at': datetime.utcnow()
    }
    comments_collection = db['comments']
    comments_collection.insert_one(comment)
    
    return jsonify({'message': '댓글 등록 성공!'}), 201

@app.route('/get_comments', methods=['GET'])
def get_comments():
    match_id = request.args.get('match_id')
    if not match_id:
        return jsonify({'message': 'match_id를 입력하세요.'}), 400

    comments_collection = db['comments']
    comments = list(comments_collection.find({'match_id': match_id}))
    
    # JSON 직렬화 가능한 형식으로 변환
    comments_data = []
    for c in comments:
        comments_data.append({
            'user_id': c.get('user_id'),
            'content': c.get('content'),
            'created_at': c.get('created_at').isoformat()
        })
        
    return jsonify({'comments': comments_data}), 200

@app.route('/get_match', methods=['GET'])
def get_match():
    match_id = request.args.get('match_id')
    if not match_id:
        return jsonify({'message': 'match_id를 입력하세요.'}), 400

    match = matches_collection.find_one({'_id': ObjectId(match_id)})
    if not match:
        return jsonify({'message': '해당 매치를 찾을 수 없습니다.'}), 404

    # JSON 직렬화 가능한 형식으로 변환
    match_data = {
        'match_id': str(match['_id']),
        'memo': match.get('memo', ''),
        'date': match.get('date', ''),
        'time_start': match.get('time_start', ''),
        'time_end': match.get('time_end', ''),
        'court_type': match.get('court_type', ''),
        'current_players': match.get('current_players', 0),
        'max_players': match.get('max_players', 0),
        'creator_id': match.get('creator_id', ''),
        'creator_name': match.get('creator_name', '알 수 없음')
    }

    return jsonify(match_data), 200

@app.route('/get_reserved_dates', methods=['GET'])
def get_reserved_dates():
    """모든 예약이 있는 날짜 리스트 반환"""
    reserved_dates = matches_collection.distinct('date', {'status': '모집중'})  # 중복 제거된 날짜 목록 가져오기
    return jsonify({'reserved_dates': reserved_dates}), 200


# 나의 예약현황
@app.route('/reservation')
def my_reservations():
    # Authorization 헤더에서 JWT 토큰 추출 ("Bearer <토큰>" 형태)
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return redirect(url_for('login'))  # 로그인 페이지로 이동

    try:
        token = auth_header.split(" ")[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        return redirect(url_for('login'))  # 토큰이 유효하지 않으면 로그인 페이지로 이동

    # JWT에서 user_id 가져오기
    user_id = payload.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    # 사용자 조회
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        return redirect(url_for('login'))

    current_user_id = str(user['_id'])

    # 내 예약 목록 조회
    my_reservations_cursor = reservations_collection.find({'user_id': current_user_id})
    reservations = []
    
    for res in my_reservations_cursor:
        match = matches_collection.find_one({'_id': ObjectId(res['creator_id'])})
        if match:
            # creator_id로 예약자의 username 찾기
            creator = users_collection.find_one({'_id': match['creator_id']})
            creator_name = creator['username'] if creator else "알 수 없음"
            
            reservations.append({
                'reservation_id': str(res['_id']),
                'match': {
                    'time_start': match.get('time_start', ''),
                    'time_end': match.get('time_end', ''),
                    'court_type': match.get('court_type', ''),
                    'memo': match.get('memo', ''),
                    'current_players': match.get('current_players', 0),
                    'max_players': match.get('max_players', 0),
                    'creator_id': str(match['creator_id']),
                    'creator_name': creator_name,  # ✅ 예약자의 이름 추가
                    '_id': str(match['_id'])
                }
            })

    return render_template('reservations.html', reservations=reservations, current_user_id=current_user_id)



@app.route('/api/reservations', methods=['GET'])
def api_reservations():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'message': 'Authorization header가 필요합니다.'}), 401

    try:
        token = auth_header.split(" ")[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        return jsonify({'message': '유효하지 않은 토큰입니다.', 'error': str(e)}), 401

    user_id = payload.get('user_id')
    if not user_id:
        return jsonify({'message': '토큰 payload에 user_id가 없습니다.'}), 401

    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
    except Exception as e:
        return jsonify({'message': '사용자 조회 오류', 'error': str(e)}), 500

    if not user:
        return jsonify({'message': '사용자를 찾을 수 없습니다.'}), 404

    current_user_id = str(user['_id'])
    my_reservations_cursor = reservations_collection.find({'user_id': current_user_id})
    reservations_data = []
    for res in my_reservations_cursor:
        match = matches_collection.find_one({'_id': ObjectId(res['match_id'])})
        if match:
            # /get_matches와 동일한 방식으로 creator_name을 조회
            creator_name = "알 수 없음"
            creator_id = match.get('creator_id')
            if ObjectId.is_valid(creator_id):
                creator = users_collection.find_one({'_id': ObjectId(creator_id)})
                if creator:
                    creator_name = creator.get('username', '알 수 없음')
            reservations_data.append({
                'reservation_id': str(res['_id']),
                'match': {
                    'date': match.get('date', ''),   # 날짜 필드 추가
                    'time_start': match.get('time_start', ''),
                    'time_end': match.get('time_end', ''),
                    'court_type': match.get('court_type', ''),
                    'memo': match.get('memo', ''),
                    'current_players': match.get('current_players', 0),
                    'max_players': match.get('max_players', 0),
                    'creator_id': match.get('creator_id', ''),
                    'creator_name': creator_name,
                    '_id': str(match['_id'])
                }
            })
    return jsonify({'reservations': reservations_data, 'current_user_id': current_user_id}), 200




# 예약자 목록 조회
@app.route('/player_list/<match_id>')
def player_list(match_id):
    reservations_cursor = reservations_collection.find({'match_id': match_id})
    players = []
    for res in reservations_cursor:
        user = users_collection.find_one({'_id': ObjectId(res['user_id'])})
        if user:
            players.append({
                'username': user.get('username', '알 수 없음'),
                'phone': user.get('phone', '알 수 없음'),
                'email': user.get('email', '')
            })
    # match 정보도 함께 조회 (예: max_players)
    match = matches_collection.find_one({'_id': ObjectId(match_id)})
    return render_template('player_list.html', players=players, match=match)

    # 모집자가 매치를 취소
@app.route('/cancel_match/<match_id>', methods=['POST'])
def cancel_match(match_id):
    # 취소 사유를 폼 데이터나 JSON으로부터 받아옴
    cancellation_reason = request.form.get('reason') or request.json.get('reason')
    if not cancellation_reason:
        return jsonify({'message': '취소 사유를 입력하세요.'}), 400

    # match_id가 MongoDB ObjectId 타입인 경우 변환
    try:
        match_obj_id = ObjectId(match_id)
    except Exception as e:
        return jsonify({'message': '유효하지 않은 match_id입니다.'}), 400

    # 모집글의 상태 업데이트: status를 "cancelled"로, 취소 사유 저장
    update_result = matches_collection.update_one(
        {'_id': match_obj_id},
        {'$set': {'status': 'cancelled', 'cancel_reason': cancellation_reason, 'cancelled_at': datetime.utcnow()}}
    )
    if update_result.modified_count == 0:
        return jsonify({'message': '모집글 취소 업데이트 실패'}), 400

    # 해당 모집글(match_id)에 신청한 예약 기록 조회
    reservations = list(reservations_collection.find({'match_id': match_id}))
    if not reservations:
        return jsonify({'message': '신청한 사람이 없습니다.'}), 200

    # 각 예약 기록의 user_id를 이용하여 사용자 이메일, username, phone 정보를 조회
    recipient_emails = []
    applicant_details = []  # 이메일 전송 외에도 정보를 로깅하거나 추가 처리 가능
    for reservation in reservations:
        user = users_collection.find_one({'_id': ObjectId(reservation['user_id'])})
        if user and 'email' in user:
            recipient_emails.append(user['email'])
            applicant_details.append({
                'username': user.get('username', '알 수 없음'),
                'phone': user.get('phone', '알 수 없음'),
                'email': user['email']
            })

    if not recipient_emails:
        return jsonify({'message': '신청자 이메일 정보를 찾을 수 없습니다.'}), 400

    # 이메일 내용 구성
    subject = "예약 취소 안내"
    body = (
        f"안녕하세요,\n\n"
        f"고객님께서 신청하신 예약이 취소되었습니다.\n"
        f"모집자 취소 사유: {cancellation_reason}\n\n"
        "불편을 드려 죄송합니다.\n"
        "감사합니다."
    )

    try:
        msg = Message(subject, recipients=recipient_emails)
        msg.body = body
        mail.send(msg)
    except Exception as e:
        return jsonify({'message': '이메일 전송 실패', 'error': str(e)}), 500

    return jsonify({'message': '모집글 취소 및 이메일 전송 성공!'}), 200

 # 참여자 예약 취소
@app.route('/cancel_reservation/<reservation_id>', methods=['POST'])
def cancel_reservation(reservation_id):
    # 예약 id로 예약 정보 조회
    reservation = reservations_collection.find_one({'_id': ObjectId(reservation_id)})
    if not reservation:
        return jsonify({'message': '예약 정보를 찾을 수 없습니다.'}), 404

    match_id = reservation['match_id']
    
    # 예약 삭제
    delete_result = reservations_collection.delete_one({'_id': ObjectId(reservation_id)})
    if delete_result.deleted_count == 0:
        return jsonify({'message': '예약 취소에 실패했습니다.'}), 400

    # 해당 match의 current_players 값을 1 감소 (최소 0 이하로 내려가지 않도록)
    match = matches_collection.find_one({'_id': ObjectId(match_id)})
    if match:
        new_current = max(match.get('current_players', 1) - 1, 0)
        matches_collection.update_one(
            {'_id': ObjectId(match_id)},
            {'$set': {'current_players': new_current}}
        )

    return jsonify({'message': '예약 취소 성공!'}), 200


if __name__ == '__main__':
    app.run(debug=True)
