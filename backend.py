from flask import request, jsonify, Flask, render_template, Response,make_response
import functools
import secrets
import datetime

app = Flask(__name__)


def validate(username, password):
    return username == app.config['USERNAME'] and password == app.config['PASSWORD']


class Cookies:
    def __init__(self):
        pass
    def __set_cookies(self):
        resp = Response()
        return resp.set_cookie(key=secrets.token_hex(32), value=secrets.token_hex(32), max_age=600,
                            expires=datetime.datetime.today(), secure=True, httponly=True, samesite="same-site")
    def get_a_cookie(self):
        return self.__set_cookies()


class Login:
    def __init__(self,f):
        self.f = f

    def __check_authorization(self):
        f = self.f
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            auth = request.authorization
            if not validate(auth.username, auth.password):
                return authenticate()
            return f(*args, **kwargs)

        return decorated
    
    def get_authorizzation(self):
        return self.__check_authorization()


@app.route('/login', methods=['GET', 'POST'])
def authenticate():
    if request.method == "GET":
        return render_template('login.html')
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        if validate(username, password):
            cookies = Cookies().get_a_cookie()
            return cookies
        else:
            return make_response(render_template('login.html'))
        
@app.route('/')
@Login.get_authorizzation
def index():
    return make_response(render_template('index.html'))
