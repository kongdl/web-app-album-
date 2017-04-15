from flask import *
import extensions
import hashlib
import uuid
import re

algorithm_1 = 'sha512'

def check_username(username, errors, create):
	error = False
	db = extensions.connect_to_database()
	cur_users = db.cursor()
	cur_users.execute('SELECT * FROM User')
	users = cur_users.fetchall()

	if create:
		if len(username) < 3:
			errors.append({"message":"Usernames must be at least 3 characters long"})
			error = True
		elif len(username) > 20:
			errors.append({"message":"Username must be no longer than 20 characters"})
			error = True

		if not re.match("^[A-Za-z0-9_]+$", username):
			errors.append({"message":"Usernames may only contain letters, digits, and underscores"})
			error = True

		if not error:
			#valid at this point, continue to check if username exists
			for user in users:
				if username.upper() == user['username'].upper():
					errors.append({"message":"This username is taken"})
					error = True

		if error:
			return False
		return True

	else:
		#check exist
		for user in users:
			if username == user['username']:
				return True

		if not error:
			errors.append({"message":"Username does not exist"})
		return False

##############################################################################
def check_password(password, errors, create):
	error = False
	if create:
		if len(password) < 8:
			error = True
			errors.append({"message":"Passwords must be at least 8 characters long"})

		if not re.match("^[A-Za-z0-9_]+$", password):
			error = True
			errors.append({"message":"Passwords may only contain letters, digits, and underscores"})

		contain_digit = any(char.isdigit() for char in password)
		contain_letter = re.search('[a-zA-Z]', password)

		if not contain_digit or not contain_letter:
			errors.append({"message":"Passwords must contain at least one letter and one number"})
			error = True

	if error:
		return False
	return True

#################################################################################
def check_name(name, errors, check_firstname):
	error = False

	if len(name) > 20:
		error = True
		if check_firstname:
			errors.append({"message":"Firstname must be no longer than 20 characters"})
		else:
			errors.append({"message":"Lastname must be no longer than 20 characters"})

	if error:
		return False
	return True

###############################################################################
def check_email(email, errors):
	error = False
	

	if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
		error = True
		errors.append({"message":"Email address must be valid"})

	if len(email) > 40:
		error = True
		errors.append({"message":"Email must be no longer than 40 characters"})

	if error:
		return False
	return True
###############################################################################

api = Blueprint('api', __name__, template_folder='templates')

@api.route('/api/v1/user',methods=['GET','POST','PUT'])
def api_v1_user_route():
	if request.method == 'GET':
		if not session.get('logged_in'):
			return jsonify( {"errors": [{ "message" : "You do not have the necessary credentials for the resource"}] }),401
		username=session.get('username')
		db = extensions.connect_to_database()
		cur_user = db.cursor()
		cur_user.execute('SELECT username,firstname,lastname,email FROM User WHERE username="%s"'%username)
		return jsonify(cur_user.fetchone()) 
	
	if request.method == 'POST': 
		error = False			
		errors=[]
		username=request.json.get('username')
		if not username:
			errors.append({"message":"You did not provide the necessary fields"})
			return jsonify({"errors":errors}),422
		if not check_username(username, errors, True):
			error = True

		firstname=request.json.get('firstname')
		if not firstname and not firstname == "":			#not sure if this is ok yet
			errors.append({"message":"You did not provide the necessary fields"})
			return jsonify({"errors":errors}),422
		if not check_name(firstname, errors, True):
			error = True

		lastname=request.json.get('lastname')
		if not lastname and not lastname == "":
			errors.append({"message":"You did not provide the necessary fields"})
			return jsonify({"errors":errors}),422
		if not check_name(lastname, errors, False):
			error = True

		email=request.json.get('email')
		if not email:
			errors.append({"message":"You did not provide the necessary fields"})
			return jsonify({"errors":errors}),422
		if not check_email(email, errors):
			error = True

		password1=request.json.get('password1')
		if not password1:
			errors.append({"message":"You did not provide the necessary fields"})
			return jsonify({"errors":errors}),422
		if not check_password(password1, errors, True):
			error = True

		password2=request.json.get('password2')
		if not password2:
			errors.append({"message":"You did not provide the necessary fields"})
			return jsonify({"errors":errors}),422
		if not password1 == password2:
			errors.append({"message":"Passwords do not match"})
			error = True

		if error:
			return jsonify({"errors":errors}),422

		salt = uuid.uuid4().hex
		m = hashlib.new(algorithm_1)
		m.update(salt + password1)
		password_hash = m.hexdigest()
		pwd_db="$".join([algorithm_1,salt,password_hash])
		db = extensions.connect_to_database()
		cur = db.cursor()
		insert_user=("INSERT INTO User VALUE (%s,%s,%s,%s,%s)")
		cur.execute(insert_user,(username,firstname,lastname,pwd_db,email))
		return jsonify({'username':username,'firstname':firstname,'lastname':lastname,'email':email})

	if request.method=='PUT':
		if not session.get('logged_in'):
			return jsonify( {"errors": [{ "message" : "You do not have the necessary credentials for the resource"}] }),401
		#403 error
		username=session.get('username')
		username_ajax=request.json.get('username')
		if not username==username_ajax:
			return jsonify( {"errors": [{ "message" : "You do not have the necessary permissions for the resource"}] }),403

		error = False			
		errors=[]
		firstname=request.json.get('firstname')
		if not firstname and not firstname=="":
			errors.append({"message":"You did not provide the necessary fields"})
			return jsonify({"errors":errors}),422
		if not check_name(firstname, errors, True):
			error = True

		lastname=request.json.get('lastname')
		if not lastname and not lastname=="":
			errors.append({"message":"You did not provide the necessary fields"})
			return jsonify({"errors":errors}),422
		if not check_name(lastname, errors, False):
			error = True

		email=request.json.get('email')
		if not email:
			errors.append({"message":"You did not provide the necessary fields"})
			return jsonify({"errors":errors}),422
		if not check_email(email, errors):
			error = True

		password1=request.json.get('password1')
		if not password1 and not password1 == "":
			errors.append({"message":"You did not provide the necessary fields"})
			return jsonify({"errors":errors}),422
		if not password1 =="":
			if not check_password(password1, errors, True):
				error = True

		password2=request.json.get('password2')
		if not password2 and not password2 == "":
			errors.append({"message":"You did not provide the necessary fields"})
			return jsonify({"errors":errors}),422
		if not password1 == password2:
			errors.append({"message":"Passwords do not match"})
			error = True

		if not error:
			db = extensions.connect_to_database()
			cur = db.cursor()

			update_firstname=("UPDATE User SET firstname=%s WHERE username=%s")
			cur.execute(update_firstname,(firstname,username))
			session['firstname']=firstname

			update_lastname=("UPDATE User SET lastname=%s WHERE username=%s")
			cur.execute(update_lastname,(lastname,username))
			session['lastname']=lastname

			if not password1=="":
				salt = uuid.uuid4().hex
				m = hashlib.new(algorithm_1)
				m.update(salt + password1)
				password_hash = m.hexdigest()
				pwd_db="$".join([algorithm_1,salt,password_hash])
				update_pwd=("UPDATE User SET password=%s WHERE username=%s")
				cur.execute(update_pwd,(pwd_db,username))

			update_email=("UPDATE User SET email=%s WHERE username=%s")
			cur.execute(update_email,(email,username))

			return jsonify({'username':username,'firstname':firstname,'lastname':lastname,'email':email})

		else:
			return jsonify({"errors":errors}), 422

@api.route('/api/v1/login',methods=['POST'])	
def api_v1_login_route():
	if session.get("logged_in")==True:
		return redirect(url_for('main.user_edit_route'))
	username=request.json.get('username')
	if not username and not username=="":
			errors.append({"message":"You did not provide the necessary fields"})
			return jsonify({"errors":errors}),422
	password=request.json.get('password')
	if not password and not password=="":
			errors.append({"message":"You did not provide the necessary fields"})
			return jsonify({"errors":errors}),422
	fault=False
	errors=[]

	if not check_username(username, errors, False):
		return jsonify({"errors":errors}),404

	if not fault:
		db = extensions.connect_to_database()
		curi = db.cursor()
		db_pw=curi.execute("SELECT password FROM User where username = '%s'" %username)
		db_pw = dict(curi.fetchone())
		check_pw = db_pw.get('password')
		salt = check_pw.split('$')[1]
		algorithm_2 = check_pw.split('$')[0]
		m = hashlib.new(algorithm_2)
		m.update(salt+password)
		password_hash = m.hexdigest()
		if password_hash == check_pw.split('$')[2]:
			cur_user = db.cursor()
			cur_user.execute('SELECT * FROM User WHERE username="%s"'%username)
			user = cur_user.fetchone()
			session['username'] = username
			session['logged_in'] = True
			session['firstname'] = user['firstname']
			session['lastname'] = user['lastname']
			return jsonify({"username":username})

		else:
			errors.append({"message":"Password is incorrect for the specified username"})
	
	return jsonify({"errors":errors}),422

@api.route('/api/v1/logout',methods=['POST'])
def api_v1_logout_route():
	if not session.get('logged_in'):
		return jsonify( {"errors": [{ "message" : "You do not have the necessary credentials for the resource"}] }),401
	session.pop('username', None)
	session['logged_in'] = False
	return ('',204)


@api.route('/api/v1/album/<albumid>',methods=['GET'])
def api_v1_album_route(albumid):
	albumid = int(albumid)
	db = extensions.connect_to_database()
	cur_user = db.cursor()

	curi_album = db.cursor()
	curi_album.execute('SELECT * FROM Album WHERE albumid = %s' %albumid)
	check_album = curi_album.fetchone()
	if not check_album or albumid==None:
		return jsonify( {"errors": [{ "message" : "The requested resource could not be found"}] }), 404
	curi_album.execute('SELECT access,created,lastupdated,title,username FROM Album WHERE albumid=%s' %albumid)
	album = curi_album.fetchone()

	if album.get('access') == 'private':
			if not session.get('logged_in'):
				return jsonify( {"errors": [{ "message" : "You do not have the necessary credentials for the resource"}] }),401
			username=session.get('username')
			cur_owner = db.cursor()
			cur_owner.execute('SELECT * FROM Album WHERE albumid=%s AND username=%s', (albumid,username))
			check_owner = cur_owner.fetchone()
			curi_album.execute('SELECT username FROM AlbumAccess WHERE albumid=%s AND username=%s', (albumid,username))
			check_username=curi_album.fetchone()

			if check_username == None and check_owner == None:
				return jsonify({"errors":[{"message": "You do not have the necessary permissions for the resource"}]}),403
	username = ""

	# client side check to be implmented

	curi_pic = db.cursor()
	curi_pic.execute('SELECT * FROM Photo,Contain WHERE Photo.picid=Contain.picid AND Contain.albumid=%s' %albumid)
	pics = curi_pic.fetchall()

	pics_list = []
	
	for pic in pics:
		pic_dict = {
			"albumid": albumid,
			"caption": pic['caption'],
			"date": pic['date'],
			"format": pic['format'],
			"picid": pic['picid'],
			"sequencenum": long(pic['sequencenum'])
		}
		pics_list.append(pic_dict)

	album_dict = {
		"access": album['access'],
		"albumid": albumid,
		"created": album['created'],
		"lastupdated": album['lastupdated'],
		"pics": pics_list,
		"title": album['title'],
		"username": album['username']
	}
	return jsonify(album_dict)

@api.route('/api/v1/pic/<picid>', methods=['GET','PUT'])
def api_pic_route(picid):
	if request.method=='GET':
		db=extensions.connect_to_database()
		if picid== None:
			return jsonify( {"errors": [{ "message" : "The requested resource could not be found"}] }),404
		cur_pic = db.cursor()
		cur_pic.execute("SELECT * FROM Photo WHERE picid='%s'" %picid)
		check_picid = cur_pic.fetchone()
		if check_picid == None:
			return jsonify( {"errors": [{ "message" : "The requested resource could not be found"}] }),404
		cur_pic.execute("SELECT albumid,caption,sequencenum FROM Contain WHERE picid='%s' " %picid )
		info_1=cur_pic.fetchone()
		cur_pic.execute("SELECT format FROM Photo WHERE picid='%s' " %picid )
		info_2=cur_pic.fetchone()
		sequencenum=info_1.get('sequencenum')
		albumid=info_1.get('albumid')
		prev_se=sequencenum-1
		next_se=sequencenum+1
		cur_pic.execute("SELECT access FROM Album WHERE albumid=%s" %albumid)
		check_album=cur_pic.fetchone()
		if check_album.get('access') == 'private':
			if not session.get('logged_in'):
				return jsonify( {"errors": [{ "message" : "You do not have the necessary credentials for the resource"}] }),401
			username=session.get('username')

			cur_owner = db.cursor()
			cur_owner.execute('SELECT * FROM Album WHERE albumid=%s AND username=%s', (albumid,username))
			check_owner = cur_owner.fetchone()

			cur_pic.execute('SELECT username FROM AlbumAccess WHERE albumid=%s AND username=%s', (albumid,username))
			check_username=cur_pic.fetchone()
			if check_username == None and check_owner == None:
				return jsonify({"errors":[{"message": "You do not have the necessary permissions for the resource"}]}), 403

		cur_pic.execute("SELECT picid FROM Contain WHERE albumid=%s AND sequencenum=%s", (albumid,prev_se))
		prev_picid=cur_pic.fetchone()
		if prev_picid!=None:
			prev_picid=prev_picid.get('picid')
		else:
			prev_picid= -1
		cur_pic.execute("SELECT picid FROM Contain WHERE albumid=%s AND sequencenum=%s", (albumid,next_se))
		next_picid=cur_pic.fetchone()
		if next_picid!=None:
			next_picid=next_picid.get('picid')
		else:
			next_picid= -1
		return jsonify({"albumid":albumid,"caption":info_1.get('caption'),"format":info_2.get('format'),"next":next_picid,"picid":picid,"prev":prev_picid})
	
	if request.method=='PUT':
		errors=[]
		albumid=request.json.get('albumid')
		#all fields are required
		if not albumid:
			errors.append({"message":"You did not provide the neccessary fields"})
			return jsonify({"errors":errors}),422

		caption=request.json.get('caption')
		if not caption and caption != "":
			errors.append({"message":"You did not provide the neccessary fields"})
			return jsonify({"errors":errors}),422
		format=request.json.get('format')
		if not format:
			errors.append({"message":"You did not provide the neccessary fields"})
			return jsonify({"errors":errors}),422
		next_picid=request.json.get('next')
		if not next_picid:
			errors.append({"message":"You did not provide the neccessary fields"})
			return jsonify({"errors":errors}),422
		get_picid=request.json.get('picid')
		if not get_picid:
			errors.append({"message":"You did not provide the neccessary fields"})
			return jsonify({"errors":errors}),422
		prev_picid=request.json.get('prev')
		if not prev_picid:
			errors.append({"message":"You did not provide the neccessary fields"})
			return jsonify({"errors":errors}),422

		db=extensions.connect_to_database()
		cur_pic = db.cursor()
		cur_pic.execute("SELECT * FROM Photo WHERE picid='%s'" %picid)
		check_picid = cur_pic.fetchone()
		#pic must exist
		if check_picid == None:
			return jsonify( {"errors": [{ "message" : "The requested resource could not be found"}] }),404
		cur_pic.execute("SELECT access FROM Album WHERE albumid=%s" %albumid)
		check_album=cur_pic.fetchone()

		#proper authoriztion
		if not session.get('logged_in'):
			return jsonify( {"errors": [{ "message" : "You do not have the necessary credentials for the resource"}] }),401
		
		username=session.get('username')
		cur_pic.execute('SELECT * FROM Album WHERE albumid=%s AND username=%s', (albumid,username))
		check_username=cur_pic.fetchone()
		if check_username == None:
			return jsonify({"errors":[{"message": "You do not have the necessary permissions for the resource"}]}), 403
		
		#only caption is modifiable
		error=False
		cur_pic.execute("SELECT albumid,sequencenum FROM Contain WHERE picid='%s'" %picid)
		check_modify_albumid=cur_pic.fetchone()
		if albumid != check_modify_albumid.get('albumid'):
			error=True
		check_se=check_modify_albumid.get('sequencenum')
		prev_se=check_se-1
		next_se=check_se+1
		cur_pic.execute('SELECT picid FROM Contain WHERE sequencenum=%s' %prev_se)
		prev=cur_pic.fetchone()
		if prev_picid != prev.get('picid') and prev_picid != -1:
			error=True

		cur_pic.execute('SELECT picid FROM Contain WHERE sequencenum=%s' %next_se)
		next=cur_pic.fetchone()

		if next_picid != next.get('picid') and next_picid != -1:
			error=True

		if get_picid != picid:
			error=True
		
		if error==False:
			cur_pic.execute('UPDATE Contain SET caption=%s WHERE picid=%s',(caption,picid))
			cur_pic.execute('UPDATE Album SET lastupdated=NOW() WHERE albumid=%s' %albumid)
			return jsonify({"albumid":albumid,"caption":caption,"format":format,"next":next_picid,"picid":picid,"prev":prev_picid}), 200
		else:
			return jsonify({"message":"You can only update caption"}), 403

