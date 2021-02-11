from enum import unique
from flask import Flask, render_template, request, redirect, flash, session, send_from_directory, url_for
from flask_sqlalchemy import SQLAlchemy
import datetime
from werkzeug.utils import secure_filename
import os 
import hashlib
import ftplib
import urllib

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'h5'}
FTP_HOST = "192.168.0.11"
FTP_USER = "transfer"
FTP_PASS = "password"

app = Flask(__name__) # creates Flask object from main fcn
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config["SECRET_KEY"] = "somekey"
db = SQLAlchemy(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

class Markers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hash = db.Column(db.String(80), nullable=False)
    filename = db.Column(db.String(80), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.datetime.now())
    commit = db.Column(db.String(80), nullable=False)
    block_stat = db.Column(db.String(80), nullable=False)
    downloaded = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return '<Marker %r>' % self.id


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return '<Users %r>' % self.username

class accessHistory(db.Model):
    transaction_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), default="None")
    marker_id = db.Column(db.String(80), nullable=False)
    access_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now())
    action = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return '<Access %r>' % self.username

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

@app.route('/', methods=['GET', 'POST'])
def index():

    return render_template('index.html')

@app.route('/track/<id>')
def show_record(id):
    vile = Markers.query.get(id)
    
    if vile is None:
        flash("Please enter a valid serial identifier!")
        return redirect('/')
    
    if not session.get("USERNAME") is None:
        newaccess = accessHistory(username = session.get("USERNAME"), marker_id = vile.id, action = "view")
    else:
        newaccess = accessHistory(marker_id = vile.id, action = "view")
    
    # db.session.add(newaccess)
    # db.session.commit()

    return render_template('show_record.html', vile=vile)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if not session.get("USERNAME") is None:
        return redirect('/profile')
    else:
        if request.method == "POST":
            username = (request.form["username"]).lower()
            password = request.form["password"]

            returned = Users.query.filter_by(username=username).first()

            if returned is None:
                flash("Incorrect username, please try again!")
                return redirect(request.url)

            if returned.password != password:
                flash("Incorrect password, please try again!")
                return redirect(request.url)

            session["USERNAME"] = username
            
            return redirect('/profile')

        return render_template('login.html')

@app.route('/profile/', methods=['GET', 'POST'])
def profile():
    if not session.get("USERNAME") is None:
        user = Users.query.filter_by(username=session.get("USERNAME")).first()
        files = Markers.query.filter_by(id=1).first()

        if len(os.listdir(os.path.join(os.path.dirname(os.path.realpath(__file__)), "uploads"))) == 0 and files is not None:
            db.session.delete(files)
            db.session.commit()
            files = Markers.query.filter_by(id=1).first()
        
        if files:
            session["FILEPRESENT"] = True

        if request.method == 'POST':
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            # if user does not select file, browser also
            # submit an empty part without filename
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                hashsum = md5(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                if files is None:
                    newfile = Markers(id=1, hash=hashsum, filename=filename, downloaded="No", commit="Queued",block_stat="Pending")
                    db.session.add(newfile)
                else:
                    files.hash = hashsum
                    files.upload_date = datetime.datetime.now()
                    files.downloaded = "No"
                    files.commit = "Queued"
                    files.block_stat = "Pending"
                    files.filename = filename
                
                session["COMMIT"] = True
                db.session.commit()

                flash("File staged and queued successfully!")
                return redirect(url_for('profile'))
                
        return render_template("profile.html", filelist=files)
    else:
        flash("Please sign in to access this page!")
        return redirect('/login')

@app.route('/profile/commit')
def commitfile():
    if not session.get("COMMIT") is None:
        files = Markers.query.filter_by(id=1).first()

        files.commit = "Yes"
        db.session.commit()
        session.pop("COMMIT", None)
        return redirect(url_for('profile'))
    else:
        return redirect(url_for('profile'))

@app.route('/profile/delete')
def deletesfile():
    if not session.get("COMMIT") is None or not session.get("FILEPRESENT") is None:
        files = Markers.query.filter_by(id=1).first()

        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], files.filename))

        db.session.delete(files)
        db.session.commit()

        session.pop("COMMIT", None)
        return redirect(url_for('profile'))
    else:
        return redirect(url_for('profile'))

@app.route('/download/<user>.<key>', methods=['GET'])
def download(user, key):
    #errorcodes: 1 = no user, 2=wrong key input, 3=deviceip not matching record, 202 = no update present, 303 = hash check failure/bad file, 505 = server issue

    request_ip = request.environ['REMOTE_ADDR'].encode('utf-8')
    username = user
    key = key

    user = Users.query.filter_by(username=username).first()
    m = hashlib.md5()
    m.update(request_ip)
    hashed_request = m.hexdigest()

    #if username not found or wrong password entered or jetson ip does not match hash then disconnect
    if user is None:
        return "E1"

    if key != user.password:
        return "E2"

    if hashed_request != user.password:
        return "E3"
    
    
    files = Markers.query.filter_by(id=1).first()
    
    if files:
        try:
            hashcheck = md5(os.path.join(app.config['UPLOAD_FOLDER'], files.filename))

            if hashcheck == files.hash:
                files.downloaded = "Yes"
                db.session.commit()

                return send_from_directory(app.config['UPLOAD_FOLDER'],
                                    files.filename, as_attachment=True)
            else:
                return "Error 303"
        except:
            return "Error 505"
    else:
        return "Error 202"



@app.route("/sign_out/")
def sign_out():
    session.pop("USERNAME", None)
    return redirect('/login')

if __name__ == '__main__': #runs Flask app
    #app.secret_key = 'some secret key'
    app.debug = True
    app.run(host= '0.0.0.0', threaded=True)
