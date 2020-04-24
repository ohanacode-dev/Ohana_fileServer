#!/usr/bin/env python3

from flask import Flask, make_response, request, render_template, send_file, Response, redirect, send_from_directory, session
from flask.views import MethodView
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import humanize
import re
import stat
import json
import mimetypes
import sys
import shutil
import random
import string
import os
import time
import hashlib


# Configuration
USER_PASSWORD = 'verySecretPassword'       # access password
LOCK_MINUTES = 5                # minutes to lock for when wrong password is entered 3 times
FILE_ROOT = os.path.expanduser('~')
GIT_ROOT = os.path.join(FILE_ROOT, '..', 'gitrepos')

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
SHAREABLE_URL_LEN = 13
SHARED_FILES = os.path.join(SCRIPT_PATH, "shared.db")
SHARE_LINK_TTL = 60*60*24

app = Flask(__name__, static_url_path='/assets', static_folder='assets')
app.secret_key = 'OCD12309876qwerty'
app.config['SESSION_TYPE'] = 'filesystem'
# app.config['SESSION_COOKIE_SECURE'] = True    # This will force cookie saving only over https.  
app.config['SESSION_COOKIE_HTTPONLY'] = True

ignored = ['.bzr', '$RECYCLE.BIN', '.DAV', '.DS_Store', '.git', '.hg', '.htaccess', '.htpasswd', '.Spotlight-V100', '.svn', '__MACOSX', 'ehthumbs.db', 'robots.txt', 'Thumbs.db', 'thumbs.tps']
datatypes = {'audio': 'm4a,mp3,oga,ogg,webma,wav', 'archive': '7z,zip,rar,gz,tar', 'image': 'gif,ico,jpe,jpeg,jpg,png,svg,webp', 'pdf': 'pdf', 'quicktime': '3g2,3gp,3gp2,3gpp,mov,qt', 'source': 'atom,bat,bash,c,cmd,coffee,css,hml,js,json,java,less,markdown,md,php,pl,py,rb,rss,sass,scpt,swift,scss,sh,xml,yml,plist', 'text': 'txt', 'video': 'mp4,m4v,ogv,webm', 'website': 'htm,html,mhtm,mhtml,xhtm,xhtml'}
icontypes = {'fa-music': 'm4a,mp3,oga,ogg,webma,wav', 'fa-archive': '7z,zip,rar,gz,tar', 'fa-picture-o': 'gif,ico,jpe,jpeg,jpg,png,svg,webp', 'fa-file-text': 'pdf', 'fa-film': '3g2,3gp,3gp2,3gpp,mov,qt,mp4,m4v,ogv,webm', 'fa-code': 'atom,plist,bat,bash,c,cmd,coffee,css,hml,js,json,java,less,markdown,md,php,pl,py,rb,rss,sass,scpt,swift,scss,sh,xml,yml', 'fa-file-text-o': 'txt', 'fa-globe': 'htm,html,mhtm,mhtml,xhtm,xhtml'}


def md5_encode(data):
    md5 = hashlib.md5()
    md5.update(data.encode('utf-8'))
    return md5.hexdigest()


def random_string(stringLength=13, solt=""):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    rnd_str = ''.join(random.choice(letters) for i in range(stringLength))
    return md5_encode(rnd_str + solt)


def load_cfg():
    global FILE_ROOT
    global GIT_ROOT
    global USER_PASSWORD

    cfg_dir = os.path.join(os.path.expanduser('~'), '.OCFS')
    cfg_file = os.path.join(cfg_dir, 'config.txt')

    if not os.path.isdir(cfg_dir):
        os.mkdir(cfg_dir)

    if not os.path.isfile(cfg_file):
        # File does not exist. Create one.
        f = open(cfg_file, 'w')
        f.write('# It is recommended to keep the GIT_ROOT out of the FILE_ROOT.\n')
        f.write('# For git repository to be cloned, paste your ssh pub key in this users .ssh/authorized_keys file\n')
        f.write('USER_PASSWORD={}\n'.format(USER_PASSWORD))
        f.write('FILE_ROOT={}\n'.format(FILE_ROOT))
        f.write('GIT_ROOT={}\n'.format(GIT_ROOT))
        f.close()

    f = open(cfg_file, 'r')
    lines = f.readlines()
    f.close()

    for line in lines:
        if '=' in line:
            data = line.split('=')

            try:
                name = data[0].strip(' ')
                val = data[1].strip(' ').strip('\n')
                if 'FILE_ROOT' in name and os.path.isdir(val):
                    FILE_ROOT = val
                elif 'GIT_ROOT' in name and os.path.isdir(val):
                    GIT_ROOT = val
                elif 'USER_PASSWORD' in name:
                    USER_PASSWORD = val
            except Exception as e:
                print("Configuration error: {}".format(e))


@app.template_filter('size_fmt')
def size_fmt(size):
    return humanize.naturalsize(size)


@app.template_filter('time_fmt')
def time_desc(timestamp):
    mdate = datetime.fromtimestamp(timestamp)
    str = mdate.strftime('%Y-%m-%d %H:%M:%S')
    return str


@app.template_filter('data_fmt')
def data_fmt(filename):
    t = 'unknown'
    for type, exts in datatypes.items():
        if filename.split('.')[-1] in exts:
            t = type
    return t


@app.template_filter('icon_fmt')
def icon_fmt(filename):
    i = 'fa-file-o'
    for icon, exts in icontypes.items():
        if filename.split('.')[-1] in exts:
            i = icon
    return i


@app.template_filter('humanize')
def time_humanize(timestamp):
    mdate = datetime.utcfromtimestamp(timestamp)
    return humanize.naturaltime(mdate)


def get_type(mode):
    if stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
        type = 'dir'
    else:
        type = 'file'
    return type


def partial_response(path, start, end=None):
    file_size = os.path.getsize(path)

    if end is None:
        end = file_size - start - 1
    end = min(end, file_size - 1)
    length = end - start + 1

    with open(path, 'rb') as fd:
        fd.seek(start)
        bytes = fd.read(length)
    assert len(bytes) == length

    response = Response(
        bytes,
        206,
        mimetype=mimetypes.guess_type(path)[0],
        direct_passthrough=True,
    )
    response.headers.add(
        'Content-Range', 'bytes {0}-{1}/{2}'.format(
            start, end, file_size,
        ),
    )
    response.headers.add(
        'Accept-Ranges', 'bytes'
    )
    return response


def get_range(request):
    range = request.headers.get('Range')
    m = re.match('bytes=(?P<start>\d+)-(?P<end>\d+)?', range)
    if m:
        start = m.group('start')
        end = m.group('end')
        start = int(start)
        if end is not None:
            end = int(end)
        return start, end
    else:
        return 0, None


def get_shareable_link(file_path):
    quicklink = None

    if os.path.isfile(os.path.join(FILE_ROOT, file_path)):

        file_urls = {}

        if os.path.isfile(SHARED_FILES):
            f = open(SHARED_FILES, "r")
            lines = f.readlines()
            f.close()

            for line in lines:
                data = line.split('=')
                if len(data) == 3:
                    path = data[0].strip()
                    if os.path.exists(os.path.join(FILE_ROOT, path)):
                        file_urls[path] = {'qurl': data[1], 'timestamp': data[2].strip()}

        letters = string.ascii_lowercase
        quicklink = ''.join(random.choice(letters) for i in range(SHAREABLE_URL_LEN))
        timestamp = '{:0f}'.format(time.time()) 

        file_urls[file_path] = {'qurl': quicklink, 'timestamp': timestamp}

        f = open(SHARED_FILES, "w")
        for relative_path in file_urls.keys():
            data = file_urls[relative_path]
            print("DATA: ".format(data))
            if (time.time() - int(data['timestamp'])) < SHARE_LINK_TTL:
                f.write("{0}={1}={2}\n".format(relative_path, data['qurl'], data['timestamp']))
        f.close()

    return quicklink


def get_file_from_shareable_link(quicklink):

    if (len(quicklink) == SHAREABLE_URL_LEN) and os.path.isfile(SHARED_FILES):
        f = open(SHARED_FILES, "r")
        lines = f.readlines()
        f.close()

        for line in lines:
            data = line.split('=')
            if len(data) == 2:
                file_path = data[0].strip()
                if (quicklink == data[1].strip()) and os.path.isfile(os.path.join(FILE_ROOT, file_path)):
                    return file_path
    return None


def zipdir(path, ziph):
    # ziph is zipfile handle
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))


def login_ok():
    client_ip = request.remote_addr
    cookie_valid = session.get('ip', client_ip) == client_ip

    return session.get('logged_in', False) and cookie_valid


class PathView(MethodView):
    def get(self, p=''):
        if '.well-known' in p:
            path = os.path.join(FILE_ROOT, '..', p)

            if os.path.isfile(path):
                if 'Range' in request.headers:
                    start, end = get_range(request)
                    res = partial_response(path, start, end)
                else:
                    res = send_file(path)
                    res.headers.add('Content-Disposition', 'attachment')
            else:
                res = make_response('Not found', 404)
            return res

        quicklink_result = get_file_from_shareable_link(p)

        if quicklink_result is not None:
            absolute_path = os.path.join(FILE_ROOT, quicklink_result)
            file_path, file_name = os.path.split(absolute_path)

            return send_from_directory(file_path, file_name, as_attachment=True)
        elif ".well-known" in p:
            hide_dotfile = 'yes'
        else:
            if not login_ok():
                return redirect("/login")

            hide_dotfile = request.args.get('hide-dotfile', request.cookies.get('hide-dotfile', 'yes'))

        if p == "favicon.ico":
            path = os.path.join(SCRIPT_PATH, p)
        else:
            path = os.path.join(FILE_ROOT, p)

        # Check if an action is requested
        action = request.args.get('action', '')
        if action != '':
            item_name = request.args.get('name', '')
            item_parent = request.args.get('path', '')

            item_path = os.path.join(FILE_ROOT, item_parent)
            relative_path = os.path.join(item_parent, item_name)
            absolute_path = os.path.join(item_path, item_name)
            share = ""
            error_msg = ""
            status = 0

            if len(item_name) > 1:
                if action == "new":
                    if not os.path.isdir(item_path):
                        status = 1
                        error_msg = "Path not found: {}".format(item_path)
                    elif os.path.isdir(absolute_path):
                        status = 1
                        error_msg = "Target already exists: {}".format(absolute_path)
                    else:
                        os.mkdir(absolute_path)

                elif action == "del":
                    if not os.path.exists(absolute_path):
                        status = 1
                        error_msg = "Path not found: {}".format(absolute_path)
                    else:
                        try:
                            if os.path.isdir(absolute_path):
                                print("Removing: ", absolute_path)
                                shutil.rmtree(absolute_path)
                            else:
                                os.remove(absolute_path)
                        except Exception as e:
                            status = 1
                            error_msg = "{}".format(e)

                elif action == "share":
                    if not os.path.exists(absolute_path):
                        status = 1
                        error_msg = "Path not found: {}".format(absolute_path)
                    else:
                        share = get_shareable_link(relative_path)

                elif action == "archive":
                    if not os.path.isdir(absolute_path):
                        status = 1
                        error_msg = "Path is not a folder: {}".format(absolute_path)
                    else:
                        shutil.make_archive(absolute_path + '_archived', 'zip', absolute_path)

                elif action == "repository":
                    if os.path.isdir(GIT_ROOT):
                        item_name = re.sub('[^0-9a-zA-Z]+', '_', item_name)
                        cmd = 'cd {} && git init --shared=0777 --bare {}.git'.format(GIT_ROOT, item_name)
                        os.system(cmd)

            else:
                status = 1
                error_msg = "Path not complete. Parent is: {0}, Item is: {1}".format(item_parent, item_name)

            res = make_response(json.JSONEncoder().encode({'status': status, 'error': error_msg, 'share': share}), 200)
            return res

        # Serve the requested item
        if os.path.isdir(path):
            contents = []

            total = {'size': 0, 'dir': 0, 'file': 0}
            for filename in os.listdir(path):
                if filename in ignored:
                    continue
                if hide_dotfile == 'yes' and filename[0] == '.':
                    continue

                try:
                    filepath = os.path.join(path, filename)
                    stat_res = os.stat(filepath)
                    info = {}
                    info['name'] = filename
                    info['mtime'] = stat_res.st_mtime
                    ft = get_type(stat_res.st_mode)
                    info['type'] = ft
                    total[ft] += 1
                    sz = stat_res.st_size
                    info['size'] = sz
                    total['size'] += sz
                    contents.append(info)
                except:
                    continue

            sorted_contents = sorted(contents, key=lambda k: k['name'])
            page = render_template('index.html', path=p, contents=sorted_contents, total=total, hide_dotfile=hide_dotfile)

            res = make_response(page, 200)
            res.set_cookie('hide-dotfile', hide_dotfile, max_age=16070400)
        elif os.path.isfile(path):
            if 'Range' in request.headers:
                start, end = get_range(request)
                res = partial_response(path, start, end)
            else:
                res = send_file(path)
                res.headers.add('Content-Disposition', 'attachment')
        else:
            if p == 'favicon.ico':
                path = os.path.join(os.path.dirname(os.path.realpath(__file__)), p)
            if os.path.isfile(path):
                res = send_file(path)
                res.headers.add('Content-Disposition', 'attachment')
            else:
                res = make_response('Not found', 404)
        return res

    def post(self, p=''):

        if not login_ok():
            return redirect("/login")

        path = os.path.join(FILE_ROOT, p)
        info = {}
        if os.path.isdir(path):
            files = request.files.getlist('files[]')
            for file in files:
                try:
                    filename = secure_filename(file.filename)
                    target_path = os.path.join(path, filename)
                    if os.path.exists(target_path):
                        info['status'] = 'error'
                        info['msg'] = "file exists: {0}".format(filename)
                    else:
                        file.save(target_path)
                        info['status'] = 'success'
                        info['msg'] = 'File Saved'
                except Exception as e:
                    info['status'] = 'error'
                    info['msg'] = str(e)
        else:
            info['status'] = 'error'
            info['msg'] = 'Invalid Operation'
        res = make_response(json.JSONEncoder().encode(info), 200)
        res.headers.add('Content-type', 'application/json')
        return res


@app.route('/login', methods=['GET', 'POST'])
def login():
    global USER_PASSWORD

    if request.method == 'POST':
        password = request.form.get("password", '')
        client_ip = request.remote_addr
        cookie_expire_date = datetime.now() + timedelta(days=1)
        timestamp = session.get('tstamp', 0)
        failure_count = session.get('failed', 0)

        message = ""
        unlocked = (time.time() - timestamp) > (LOCK_MINUTES * 60)
        cookie_valid = session.get('ip', client_ip) == client_ip

        session['ip'] = client_ip

        if unlocked and cookie_valid and (password == USER_PASSWORD) and failure_count < 3:
            session['failed'] = 0
            session['logged_in'] = True
            response = make_response(redirect('/'))

        else:
            session['failed'] += 1
            session['logged_in'] = False

            if session['failed'] == 1:
                message = 'ERROR: Wrong password!'
            elif session['failed'] == 2:
                message = 'ERROR: Wrong password second time. One more and we will lock up the server.'
            elif session['failed'] == 3:
                session['tstamp'] = time.time()
                message = 'ERROR: Wrong password too many times. The server is temporally locked. Please try again later.'
            elif session['failed'] > 3:
                message = 'The server is temporally locked. Please try again later.'

            response = make_response(render_template('login.html', message=message))

        response.set_cookie('dummy', '', expires=cookie_expire_date)
        return response
    else:
        message = request.args.get("message")
        response = make_response(render_template('login.html', message=message))
        response.set_cookie('dummy', '', expires=datetime.now())
        return response


@app.route('/logout', methods=['GET'])
def logout():
    session.pop('logged_in')
    response = make_response(redirect('/login'))
    response.set_cookie('dummy', '', expires=datetime.now())

    return response


@app.route('/git', methods=['GET', 'POST'])
def gitrepos():

    if not login_ok():
        return redirect("/login")
    else:
        contents = []
        if os.path.isdir(GIT_ROOT):
            for filename in os.listdir(GIT_ROOT):
                filepath = os.path.join(GIT_ROOT, filename)
                if os.path.isdir(filepath):
                    if filename.endswith('.git'):
                        filename = filename[:-4]
                    info = {}
                    info['name'] = filename
                    info['clone'] = filename.split('.git')[0]
                    contents.append(info)
        else:
            cfg_dir = os.path.join(os.path.expanduser('~'), '.OCFS')
            cfg_file = os.path.join(cfg_dir, 'config.txt')

            info = {}
            info['name'] = 'Please configure git root in: {}'.format(cfg_file)
            info['clone'] = ''
            contents.append(info)

        sorted_contents = sorted(contents, key=lambda k: k['name'])

        return render_template('git.html', contents=sorted_contents, git_root=GIT_ROOT)


@app.route('/admin', methods=['GET'])
def admin():
    cmd = request.args.get('cmd', '')
    password = request.form.get('password', '')
    client_ip = request.remote_addr
    cookie_expire_date = datetime.now() + timedelta(days=1)
    timestamp = session.get('tstamp', 0)
    failure_count = session.get('failed', 0)

    message = ""
    unlocked = (time.time() - timestamp).seconds > (LOCK_MINUTES * 60)
    cookie_valid = session.get('ip', client_ip) == client_ip

    session['ip'] = client_ip

    if unlocked and cookie_valid and (password == USER_PASSWORD) and failure_count < 3:
        if cmd == "shutdown":
            func = request.environ.get('werkzeug.server.shutdown')
            if func is None:
                sys.exit(4)
            func()
            message = 'Server shutting down!'
        else:
            message = 'Error: command not implemented!'
    else:
        session['failed'] += 1
        session['logged_in'] = False

        if session['failed'] == 1:
            message = 'ERROR: Wrong password!'
        elif session['failed'] == 2:
            message = 'ERROR: Wrong password second time. One more and we will lock up the server.'
        elif session['failed'] == 3:
            session['tstamp'] = time.time()
            message = 'ERROR: Wrong password too many times. The server is temporally locked. Please try again later.'
        elif session['failed'] > 3:
            message = 'The server is temporally locked. Please try again later.'

    response = make_response(json.JSONEncoder().encode({'msg': message}), 200)
    response.set_cookie('dummy', '', expires=cookie_expire_date)
    return response


load_cfg()
path_view = PathView.as_view('path_view')
app.add_url_rule('/', view_func=path_view)
app.add_url_rule('/<path:p>', view_func=path_view)

if __name__ == '__main__':
    app.run('0.0.0.0', 8888, threaded=True, debug=False)
