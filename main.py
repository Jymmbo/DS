#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import urllib
import re
import hashlib, uuid

from google.appengine.api import users
from google.appengine.ext import ndb
from google.appengine.api import images
from google.appengine.ext import webapp
from google.appengine.ext import blobstore
from google.appengine.ext import db
from google.appengine.ext.webapp import blobstore_handlers
from base64 import b64encode


#from urkolarraapppiedra.token import generate_confirmation_token, confirm_token
#import datetime


import json
import jinja2
import webapp2

from webapp2_extras import sessions
import session_module

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

class MainHandler(webapp2.RequestHandler):
	def get(self):
		template_values = { 'idioma': 'eus' }
		template = JINJA_ENVIRONMENT.get_template('index.html')
		self.response.write(template.render(template_values))
	
	def post(self):
		template_values = { 'idioma': 'eus',
						   'msgRellene': 'Bete eremuak, mesedez:',
						  'msgNomUser': 'Erabiltzailea',
						  'msgPass': 'Pasahitza',
						   'msgPassRep': 'Errepikatu pasahitza',
						   'msgEmail': 'Email-a',
						   'msgAvatar': 'Zure irudia',
						   'msgButEnviar': 'Bidali'}
		template = JINJA_ENVIRONMENT.get_template('registro.html')
		self.response.write(template.render(template_values))

class MainHandlerEs(webapp2.RequestHandler):
	def get(self):
		template_values = { 'idioma': 'es' }
		template = JINJA_ENVIRONMENT.get_template('index.html')
		self.response.write(template.render(template_values))
		
	def post(self):
		template_values = { 'idioma': 'es',
						   'msgRellene': 'Rellene los campos, por favor:',
						  'msgNomUser': 'Nombre de usuario',
						  'msgPass': 'Password',
						   'msgPassRep': 'Repetir password',
						   'msgEmail': 'Email',
						   'msgAvatar': 'Foto',
						   'msgButEnviar': 'Enviar'}
		template = JINJA_ENVIRONMENT.get_template('registroes.html')
		self.response.write(template.render(template_values))

class MainHandlerEn(webapp2.RequestHandler):
	def get(self):
		template_values = { 'idioma': 'en' }
		template = JINJA_ENVIRONMENT.get_template('index.html')
		self.response.write(template.render(template_values))
		
	def post(self):
		template_values = { 'idioma': 'en',
						   'msgRellene': 'Fill in the gaps, please:',
						  'msgNomUser': 'User',
						  'msgPass': 'Password',
						   'msgPassRep': 'Repeat password',
						   'msgEmail': 'Email',
						   'msgAvatar': 'Photo',
						   'msgButEnviar': 'Submit'}
		template = JINJA_ENVIRONMENT.get_template('registroen.html')
		self.response.write(template.render(template_values))


class Registrarse(webapp2.RequestHandler):
	def get(self):
		template_values = { 'idioma': 'eus',
						   'msgRellene': 'Bete eremuak, mesedez:',
						  'msgNomUser': 'Erabiltzailea',
						  'msgPass': 'Pasahitza',
						   'msgPassRep': 'Errepikatu pasahitza',
						   'msgEmail': 'Email-a',
						   'msgAvatar': 'Zure irudia',
						   'msgButEnviar': 'Bidali'}
		template = JINJA_ENVIRONMENT.get_template('registro.html')
		self.response.write(template.render(template_values))
	
	def post(self):
		nombre=self.request.get('username')
		password=self.request.get('password')
		passwordRep=self.request.get('passwordrep')
		email=self.request.get('email')
		avatar = self.request.get('imagen')
		msgUserError = ""
		msgPassError = ""
		msgPass2Error = ""
		msgEmailError = ""
		msgCorrectoAlmacenado = ""
		USERRE = re.compile(r"^[a-zA-Z0-9]+([a-zA-Z0-9](_|-| )[a-zA-Z0-9])*[a-zA-Z0-9]+$")
		passRe = re.compile(r"([a-zA-Z0-9]{6,20})$")
		emailRe = re.compile(r"^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,3})$")
		errorVal = False

		if not USERRE.match(nombre):
			msgUserError = "Erabiltzailearen izena ez da zuzena"
			errorVal = True
		if not passRe.match(password):
			msgPassError = "Pasahitza ez da zuzena"
			errorVal = True
		if not password == passwordRep:
			msgPass2Error = "Pasahitzek ez dute bat egiten"
			errorVal = True
		if not emailRe.match(email):
			msgEmailError = "Emaila gaizki sartu duzu"
			errorVal = True
		
		if not errorVal:
			nusersnombre = User.query(User.nombre==nombre).count()
			nusersemail = User.query(User.email==email).count()
			if (nusersnombre==1):
				msgUserError = "Dagoeneko bada izen hori duen erabiltzaile bat"
			elif (nusersemail==1):
				msgEmailError = "Dagoeneko bada email hori duen erabiltzaile bat"
			else:
				datos = User()
				try:
					avatar = images.resize(avatar, 150, 150)
					datos.foto = avatar
				except:
					count = 0
				
				datos.nombre = nombre
				datos.password = password
				datos.email = email
				datos.put()
				msgCorrectoAlmacenado = "ZORIONAK! "  + nombre + ", zure erabiltzailea ongi gorde dugu"

		template_values = { 'idioma': 'eus',
							'username': nombre,
							'password': password,
							'passwordRep': passwordRep,
							'email': email,
						   'imagen': avatar,
						   'msgRellene': 'Bete eremuak, mesedez:',
						  'msgNomUser': 'Erabiltzailea',
						  'msgPass': 'Pasahitza',
						   'msgPassRep': 'Errepikatu pasahitza',
						   'msgEmail': 'Email-a',
						   'msgAvatar': 'Zure irudia',
						   'msgButEnviar': 'Bidali',
						  'msgHola': 'Kaixo',
						  'msgDatosOK': 'Zure datuak ongi daude',
						  'msgNomUserE': msgUserError,
						  'msgPassE': msgPassError,
						   'msgPassRepE': msgPass2Error,
						   'msgEmailE': msgEmailError,
						   'msgCorrectoAlmacenado': msgCorrectoAlmacenado}
		template = JINJA_ENVIRONMENT.get_template('registro.html')
		self.response.write(template.render(template_values))

class RegistrarseEs(webapp2.RequestHandler):
	def get(self):
		template_values = { 'idioma': 'es',
						   'msgRellene': 'Rellene los campos, por favor:',
						  'msgNomUser': 'Nombre de usuario',
						  'msgPass': 'Password',
						   'msgPassRep': 'Repetir password',
						   'msgEmail': 'Email',
						   'msgAvatar': 'Foto',
						   'msgButEnviar': 'Enviar'}
		template = JINJA_ENVIRONMENT.get_template('registroes.html')
		self.response.write(template.render(template_values))
	
	def post(self):
		nombre=self.request.get('username')
		password=self.request.get('password')
		passwordRep=self.request.get('passwordrep')
		email=self.request.get('email')
		avatar = self.request.get('imagen')
		msgUserError = ""
		msgPassError = ""
		msgPass2Error = ""
		msgEmailError = ""
		msgCorrectoAlmacenado = ""
		USERRE = re.compile(r"^[a-zA-Z0-9]+([a-zA-Z0-9](_|-| )[a-zA-Z0-9])*[a-zA-Z0-9]+$")
		passRe = re.compile(r"([a-zA-Z0-9]{6,20})$")
		emailRe = re.compile(r"^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,3})$")
		errorVal = False

		if not USERRE.match(nombre):
			msgUserError = "Nombre de usuario incorrecto"
			errorVal = True
		if not passRe.match(password):
			msgPassError = "El password no es correcta"
			errorVal = True
		if not password == passwordRep:
			msgPass2Error = "Los passwords no coinciden"
			errorVal = True
		if not emailRe.match(email):
			msgEmailError = "Email incorrecto"
			errorVal = True
		
		if not errorVal:
			nusersnombre = User.query(User.nombre==nombre).count()
			nusersemail = User.query(User.email==email).count()
			if (nusersnombre==1):
				msgUserError = "Ya existe un usuario con ese nombre"
			elif (nusersemail==1):
				msgEmailError = "Ya existe un usuario con ese email"
			else:
				datos = User()
				try:
					avatar = images.resize(avatar, 150, 150)
					datos.foto = avatar
				except:
					count = 0
				
				datos.nombre = nombre
				datos.password = password
				datos.email = email
				datos.put()
				msgCorrectoAlmacenado = "FELICIDADES! "  + nombre + ", tu usuario se ha guardado correctamente"

		template_values = { 'idioma': 'es',
							'username': nombre,
							'password': password,
							'passwordRep': passwordRep,
							'email': email,
						   'imagen': avatar,
						   'msgRellene': 'Rellene los campos, por favor:',
						   'msgNomUser': 'Nombre de usuario',
						   'msgPass': 'Password',
						   'msgPassRep': 'Repetir password',
						   'msgEmail': 'Email',
						   'msgAvatar': 'Foto',
						   'msgButEnviar': 'Enviar',
						   'msgHola': 'Hola',
						  'msgDatosOK': 'Tus datos son correctos',
						  'msgNomUserE': msgUserError,
						  'msgPassE': msgPassError,
						   'msgPassRepE': msgPass2Error,
						   'msgEmailE': msgEmailError,
						   'msgCorrectoAlmacenado': msgCorrectoAlmacenado}
		template = JINJA_ENVIRONMENT.get_template('registroes.html')
		self.response.write(template.render(template_values))

class RegistrarseEn(webapp2.RequestHandler):
	def get(self):
		template_values = { 'idioma': 'en',
						   'msgRellene': 'Fill in the gaps, please:',
						  'msgNomUser': 'User',
						  'msgPass': 'Password',
						   'msgPassRep': 'Repeat password',
						   'msgEmail': 'Email',
						   'msgAvatar': 'Photo',
						   'msgButEnviar': 'Submit'}
		template = JINJA_ENVIRONMENT.get_template('registroen.html')
		self.response.write(template.render(template_values))
	
	def post(self):
		nombre=self.request.get('username')
		password=self.request.get('password')
		passwordRep=self.request.get('passwordrep')
		email=self.request.get('email')
		avatar = self.request.get('imagen')
		msgUserError = ""
		msgPassError = ""
		msgPass2Error = ""
		msgEmailError = ""
		msgCorrectoAlmacenado = ""
		USERRE = re.compile(r"^[a-zA-Z0-9]+([a-zA-Z0-9](_|-| )[a-zA-Z0-9])*[a-zA-Z0-9]+$")
		passRe = re.compile(r"([a-zA-Z0-9]{6,20})$")
		emailRe = re.compile(r"^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,3})$")
		errorVal = False

		if not USERRE.match(nombre):
			msgUserError = "The name is incorrect!"
			errorVal = True
		if not passRe.match(password):
			msgPassError = "The password is incorrect!"
			errorVal = True
		if not password == passwordRep:
			msgPass2Error = "Passwords do not match!"
			errorVal = True
		if not emailRe.match(email):
			msgEmailError = "The emai is incorrect!"
			errorVal = True
		
		if not errorVal:
			nusersnombre = User.query(User.nombre==nombre).count()
			nusersemail = User.query(User.email==email).count()
			if (nusersnombre==1):
				msgUserError = "A user with that name already exists"
			elif (nusersemail==1):
				msgEmailError = "A user with that email already exists"
			else:
				datos = User()
				try:
					avatar = images.resize(avatar, 150, 150)
					datos.foto = avatar
				except:
					count = 0
				
				datos.nombre = nombre
				datos.password = password
				datos.email = email
				datos.put()
				msgCorrectoAlmacenado = "CONGRATULATIONS! "  + nombre + ", your user has been successfully saved"

		template_values = { 'idioma': 'en',
							'username': nombre,
							'password': password,
							'passwordRep': passwordRep,
							'email': email,
						   'imagen': avatar,
						   'msgRellene': 'Fill in the gaps, please:',
						  'msgNomUser': 'User',
						  'msgPass': 'Password',
						   'msgPassRep': 'Repeat password',
						   'msgEmail': 'Email',
						   'msgAvatar': 'Photo',
						   'msgButEnviar': 'Submit',
						   'msgHola': 'Hello',
						  'msgDatosOK': 'Your data are well',
						  'msgNomUserE': msgUserError,
						  'msgPassE': msgPassError,
						   'msgPassRepE': msgPass2Error,
						   'msgEmailE': msgEmailError,
						   'msgCorrectoAlmacenado': msgCorrectoAlmacenado}
		template = JINJA_ENVIRONMENT.get_template('registroen.html')
		self.response.write(template.render(template_values))

class VerUsuarios(webapp2.RequestHandler):
	def get(self):
		listausuarios = User.query()
		for user in listausuarios:
			try:
				image = b64encode(user.foto)
				user.foto = image
			except Exception:
				count = 0
			
		listausuarios = User.query()
		template_values = {'idioma': 'eus',
						   'listausers': listausuarios}
		template = JINJA_ENVIRONMENT.get_template('listausuarios.html')
		self.response.write(template.render(template_values))

class VerUsuariosEs(webapp2.RequestHandler):
	def get(self):
		listausuarios = User.query()
		for user in listausuarios:
			try:
				image = b64encode(user.foto)
				user.foto = image
			except Exception:
				count = 0
			
		listausuarios = User.query()
		template_values = {'idioma': 'es',
						   'listausers': listausuarios}
		template = JINJA_ENVIRONMENT.get_template('listausuarios.html')
		self.response.write(template.render(template_values))

class VerUsuariosEn(webapp2.RequestHandler):
	def get(self):
		listausuarios = User.query()
		for user in listausuarios:
			try:
				image = b64encode(user.foto)
				user.foto = image
			except Exception:
				count = 0
			
		listausuarios = User.query()
		template_values = {'idioma': 'en',
						   'listausers': listausuarios}
		template = JINJA_ENVIRONMENT.get_template('listausuarios.html')
		self.response.write(template.render(template_values))

class User(ndb.Model):
	nombre = ndb.StringProperty(required=True)
	email = ndb.StringProperty(required=True)
	password = ndb.StringProperty(required=True)
	foto = ndb.BlobProperty(required=False)
	created=ndb.DateTimeProperty(auto_now_add=True)

class ValidarEmail(webapp2.RequestHandler):
	def get(self):
		codigoValidacion = ""
		email = self.request.get('email')
		nusersemail = User.query(User.email==email).count()
		if (nusersemail==1):
			codigoValidacion = "0"
		else:
			codigoValidacion = "1"
		
		self.response.out.write("%s" %(codigoValidacion))

# Las tares 5.1, 5.2, 6 y 7 solo van en castellano

class Geolocalizacion(webapp2.RequestHandler):
	def get(self):
		template_values = {'msgDireccion': 'Direccion:',
						   'msgDireccionE': 'Direccion incorrecta'}
		template = JINJA_ENVIRONMENT.get_template('geolocalizacion.html')
		self.response.write(template.render(template_values))

class Mostrarmapa(webapp2.RequestHandler):
	def get(self):
		serviceurl = 'http://maps.googleapis.com/maps/api/geocode/json?'
		address=self.request.get('dir')
		url = serviceurl + urllib.urlencode({'address': address})
		uh = urllib.urlopen(url)
		data = uh.read()
		
		js = json.loads(str(data))
		lat = js['results'][0]['geometry']['location']['lat']
		lng = js['results'][0]['geometry']['location']['lng']
		
		#self.response.out.write("%s" %js)
		self.response.out.write("%s,%s"%(lat,lng))

class Autenticacion(webapp2.RequestHandler):
	def get(self):
		template_values = {}
		template = JINJA_ENVIRONMENT.get_template('autenticacion.html')
		self.response.write(template.render(template_values))

#TAREA 6
class Usuarios(ndb.Model):
	name = ndb.StringProperty(required=True)
	email = ndb.StringProperty(required=True)
	password = ndb.StringProperty(required=True)
	activo = ndb.BooleanProperty()
	salero = ndb.StringProperty(required=True)
	date=ndb.DateTimeProperty(auto_now_add=True)

class Image(ndb.Model):
	user = ndb.StringProperty()
	public = ndb.BooleanProperty()
	blob_key = ndb.BlobKeyProperty()

# Primera clase en la que miramos si el usuario esta logeado
class AccesoLogin(session_module.BaseSessionHandler):
	def get(self):
		registrado = "0"
		if self.session.get('registrado'):
			#Como esta registrado, le ponemos valor 1
			registrado = "1"

		template_values = {'registrado': registrado}
		template = JINJA_ENVIRONMENT.get_template('tareaseis.html')
		self.response.write(template.render(template_values))

class ValidarEmail2(webapp2.RequestHandler):
	def get(self):
		codigoValidacion = ""
		email = self.request.get('email')
		nusersemail = Usuarios.query(Usuarios.email==email).count()
		if (nusersemail==1):
			codigoValidacion = "0"
		else:
			codigoValidacion = "1"
		
		self.response.out.write("%s" %(codigoValidacion))

class RegistrarseEs2(session_module.BaseSessionHandler):
	def get(self):
		template_values = { 'idioma': 'es',
						   'msgRellene': 'Rellene los campos, por favor:'}
		template = JINJA_ENVIRONMENT.get_template('registrotareaseis.html')
		self.response.write(template.render(template_values))
	
	def post(self):
		nombre=self.request.get('username')
		password=self.request.get('password')
		passwordRep=self.request.get('passwordrep')
		email=self.request.get('email')
		msgUserError = ""
		msgPassError = ""
		msgPass2Error = ""
		msgEmailError = ""
		msgCorrecto = ""
		USERRE = re.compile(r"^[a-zA-Z0-9]+([a-zA-Z0-9](_|-| )[a-zA-Z0-9])*[a-zA-Z0-9]+$")
		passRe = re.compile(r"([a-zA-Z0-9]{6,20})$")
		emailRe = re.compile(r"^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,3})$")
		errorVal = False
		registradoYa = False

		if self.session.get('registrado'):
			registrado = self.session.get('registrado')
			if registrado == "1":
				registradoYa = True
				msgCorrecto = "Un usuario logueado no puede registrarse"
		
		if not USERRE.match(nombre):
			msgUserError = "Nombre de usuario incorrecto"
			errorVal = True
		if not passRe.match(password):
			msgPassError = "El password no es correcto"
			errorVal = True
		if not password == passwordRep:
			msgPass2Error = "Los passwords no coinciden"
			errorVal = True
		if not emailRe.match(email):
			msgEmailError = "Email incorrecto"
			errorVal = True
		
		if not errorVal and not registradoYa:
			nusersnombre = Usuarios.query(Usuarios.name==nombre).count()
			nusersemail = Usuarios.query(Usuarios.email==email).count()
			if (nusersnombre==1):
				msgUserError = "Ya existe un usuario con ese nombre"
				errorVal = True
			elif (nusersemail==1):
				msgEmailError = "Ya existe un usuario con ese email"
				errorVal = True
			else:
				datos = Usuarios()
				datos.name = nombre
				salt = uuid.uuid4().hex
				datos.salero = salt
				hashed_password = hashlib.sha512(password + salt).hexdigest()
				datos.password = hashed_password
				datos.email = email
				datos.activo = True
				datos.put()
				msgCorrecto = "FELICIDADES! "  + nombre + ", tu usuario se ha registrado correctamente"

		template_values = { 'idioma': 'es',
							'username': nombre,
							'password': password,
							'passwordRep': passwordRep,
							'email': email,
						   'msgRellene': 'Rellene los campos, por favor:',
						   'msgNomUser': 'Nombre de usuario',
						   'msgPass': 'Password',
						   'msgPassRep': 'Repetir password',
						   'msgEmail': 'Email',
						   'msgButEnviar': 'Enviar',
						   'msgHola': 'Hola',
						  'msgDatosOK': 'Tus datos son correctos',
						  'msgNomUserE': msgUserError,
						  'msgPassE': msgPassError,
						   'msgPassRepE': msgPass2Error,
						   'msgEmailE': msgEmailError,
						   'msgCorrecto': msgCorrecto,}
		
		if errorVal or registradoYa:
			template = JINJA_ENVIRONMENT.get_template('registrotareaseis.html')
		else:
			template = JINJA_ENVIRONMENT.get_template('tareaseis.html')
		
		self.response.write(template.render(template_values))

class Login(session_module.BaseSessionHandler):
	def get(self):
		template_values = { 'idioma': 'es',
						   'msgRellene': 'Rellene los campos, por favor:'}
		template = JINJA_ENVIRONMENT.get_template('login.html')
		self.response.write(template.render(template_values))
	
	def post(self):
		password=self.request.get('password')
		email=self.request.get('email')
		msgError = ""
		msgCorrecto = ""
		passRe = re.compile(r"([a-zA-Z0-9]{6,20})$")
		emailRe = re.compile(r"^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,3})$")
		errorVal = False
		registrado = "0"

		if not passRe.match(password):
			errorVal = True
		if not emailRe.match(email):
			errorVal = True
		
		if not errorVal:
			existeUsuario = Usuarios.query(Usuarios.email==email, Usuarios.activo==True).count()
			if (existeUsuario==1):
				users = Usuarios.query(Usuarios.email==email)
				for user in users:
					salt = user.salero
					pass_bbdd = user.password
				
				pass_login = hashlib.sha512(password + salt).hexdigest()
				if not pass_bbdd==pass_login:
					errorVal = True
					#msgError = "3 " + pass_bbdd + "-----" + pass_login + "-----" + password + "-----" + salt
					#Controlamos el numero de intentos que lleva el usuario
					intentos = 0
					if self.session.get('usuariologeando'):
						usuariolog = self.session.get('usuariologeando')
						if(usuariolog==email):
							if self.session.get('intentos'):
								intentos = self.session.get('intentos')
								self.session['intentos'] = intentos + 1
							else:
								intentos = 1
								self.session['intentos'] = 1
						else:
							self.session['usuariologeando'] = email
							intentos = 1
							self.session['intentos'] = 1
					else:
						self.session['usuariologeando'] = email
						intentos = 1
						self.session['intentos'] = 1
					
					if(intentos>2):
						msgError = "Su cuenta ha sido bloqueada. No ha conseguido loguearse en tres ocasiones"
						#Codigo de bloqueo de la cuenta del usuario -> modificar el estado del usuario, activo=False
						users = Usuarios.query(Usuarios.email==email)
						for l in users.fetch(limit = 1):
							l.activo = False
							l.put()
				
				else:
					#Indicamos en session que esta registrado
					self.session['usuariologeando'] = email
					registrado = "1"
					self.session['registrado'] = registrado
			else:
				errorVal = True

		if not errorVal:
			msgCorrecto = "LOGUEADO!"
			template = JINJA_ENVIRONMENT.get_template('tareaseis.html')
		else:
			template = JINJA_ENVIRONMENT.get_template('login.html')
			if msgError == "":
				msgError = msgError + " El inicio de sesion ha fallado. Hay elementos incorrectos"
			template = JINJA_ENVIRONMENT.get_template('login.html')
			
		template_values = { 'idioma': 'es',
							'password': password,
							'email': email,
						   'msgRellene': 'Rellene los campos, por favor:',
						   'msgPass': 'Password',
						   'msgEmail': 'Email',
						   'msgButEnviar': 'Enviar',
						   'msgError': msgError,
						  'msgCorrecto': msgCorrecto,
						  'registrado': registrado}
		#template = JINJA_ENVIRONMENT.get_template('login.html')
		self.response.write(template.render(template_values))

class Logout(session_module.BaseSessionHandler):
	def get(self):
		if self.session.get('registrado'):
			del self.session['registrado']
		if self.session.get('usuariologeando'):
			del self.session['usuariologeando']
		template_values = {'msgCorrecto': "Sesion finalizada"}
		template = JINJA_ENVIRONMENT.get_template('tareaseis.html')
		self.response.write(template.render(template_values))

class AddFoto2(blobstore_handlers.BlobstoreUploadHandler, session_module.BaseSessionHandler):
	def get(self):
		FORM_SUBIR_FOTO="""
		<html><body>
		<form action="%(url)s" method="POST" enctype="multipart/form-data">
		<input type="file" name="file"><br>
		<input type="radio" name="access" value="public" checked="checked" />    Public
		<input type="radio" name="access" value="private" /> Private<p>
		<input type="submit" name="submit" value="Submit">
		</form></body></html>"""
		upload_url = blobstore.create_upload_url('/addfoto')
		self.response.out.write(FORM_SUBIR_FOTO % {'url':upload_url})
	
	def post(self):
		upload_files = self.get_uploads('file')
		blob_info = upload_files[0] # guardo la imagen en el BlobStore
		img = Image(user=self.session.get('usuariologeando'),public=self.request.get("access")=="public",blob_key=blob_info.key())
		img.put() #guardo el objeto Image


class AddFoto(blobstore_handlers.BlobstoreUploadHandler, session_module.BaseSessionHandler):
	def get(self):
		upload_url = blobstore.create_upload_url('/addfoto')
		template_values = {'upload_url': upload_url}
		template = JINJA_ENVIRONMENT.get_template('addfoto.html')
		self.response.write(template.render(template_values))
	
	def post(self):
		if "public"==self.request.get('access'):
			publicFot = True
		else:
			publicFot = False
		msgProcesoImagen = ""
		if self.session.get('usuariologeando'):
			if self.session.get('registrado'):
				registrado = self.session.get('registrado')
				if registrado == "1":
					upload_files = self.get_uploads('imagen')
					blob_info = upload_files[0] # guardo la imagen en el BlobStore

					
					#avatar = self.request.get('imagen')
					imagen = Image()
					imagen.user = self.session.get('usuariologeando')
					imagen.public = publicFot
					imagen.blob_key = blob_info.key()
					imagen.put()
					
					#try:
					#	avatar = self.get_uploads('imagen')
					#	blob_info = avatar[0] # guardo la imagen en el BlobStore
					#	img = Image(user=self.session.get('usuariologeando'),
					#				public=self.request.get("access")=="public",
					#				blob_key=blob_info.key())
					#	img.put() #guardo el objeto Image
					#except:
					#	count = 0
					msgProcesoImagen = "Imagen almacenada correctamente: " + self.request.get('access')
				else:
					msgProcesoImagen = "Lo siento, no se encuentra logueado. No podra subir ninguna foto!"
			else:
				msgProcesoImagen = "Lo siento, no se encuentra logueado. No podra subir ninguna foto!"
		else:
			msgProcesoImagen = "Lo siento, no se encuentra logueado. No podra subir ninguna foto!"
		
		template_values = { 'msgProcesoImagen': msgProcesoImagen}
		template = JINJA_ENVIRONMENT.get_template('addfotovolver.html')
		self.response.write(template.render(template_values))

class VerFotos(session_module.BaseSessionHandler):
	def get(self):
		versolopublicas = True
		if self.session.get('registrado'):
			registrado = self.session.get('registrado')
			if registrado == "1":
				versolopublicas = False
		
		fotos= blobstore.BlobInfo.all()
		if versolopublicas:
			for foto in fotos:
				existeUsuario = Image.query(Image.public==True,Image.blob_key==foto.key()).count()
				if existeUsuario==1:
					self.response.out.write('<img src="serve/%s" height="200"></image></td>' %foto.key())
		else:
			for foto in fotos:
				existeUsuario = Image.query(Image.public==True,Image.blob_key==foto.key()).count()
				if existeUsuario==1:
					self.response.out.write('<img src="serve/%s" height="200"></image></td>' %foto.key())
				else:
					existeUsuario = Image.query(Image.public==False,Image.blob_key==foto.key(),
												Image.user==str(self.session.get('usuariologeando'))).count()
					if existeUsuario>=1:
						self.response.out.write('<img src="serve/%s" height="200"></image></td>' %foto.key())
		
		template_values = {}
		template = JINJA_ENVIRONMENT.get_template('listafotos.html')
		self.response.write(template.render(template_values))

class ServeHandler(blobstore_handlers.BlobstoreDownloadHandler):
	def get(self, resource):
		resource = str(urllib.unquote(resource))
		blob_info = blobstore.BlobInfo.get(resource)
		self.send_blob(blob_info)

class ModificarUsuario(session_module.BaseSessionHandler):
	def get(self):
		msg = ""
		usuariolog = ""
		usuarioname = ""
		#Lo primero, cargamos los datos de usuario
		if self.session.get('usuariologeando'):
			usuariolog = self.session.get('usuariologeando')
			existeUsuario = Usuarios.query(Usuarios.email==usuariolog, Usuarios.activo==True).count()
			if (existeUsuario==1):
				users = Usuarios.query(Usuarios.email==usuariolog)
				for user in users:
					usuarioname = user.name
			else:
				msg = "Ha ocurrido un error. Usted no puede modificar los datos"
		else:
			msg = "Ha ocurrido un error. Usted no se encuentra logueado"
		
		template_values = {'msg': msg,
						  'username': usuarioname,
						  'email': usuariolog,
						  'msgRellene': 'Rellene los campos, por favor:'}
		template = JINJA_ENVIRONMENT.get_template('modificarusuario.html')
		self.response.write(template.render(template_values))			
	
	def post(self):
		nombre=self.request.get('username')
		passwordAntiguo=self.request.get('passwordAntiguo')
		password=self.request.get('password')
		passwordRep=self.request.get('passwordrep')
		email=self.request.get('email')
		msgUserError = ""
		msgPassAntiguoError = ""
		msgPassError = ""
		msgPass2Error = ""
		msgEmailError = ""
		msgCorrecto = ""
		msg = ""
		USERRE = re.compile(r"^[a-zA-Z0-9]+([a-zA-Z0-9](_|-| )[a-zA-Z0-9])*[a-zA-Z0-9]+$")
		passRe = re.compile(r"([a-zA-Z0-9]{6,20})$")
		errorVal = False
		registrado = "0"
		
		if not USERRE.match(nombre):
			msgUserError = "Nombre de usuario incorrecto"
			errorVal = True
		if not passRe.match(passwordAntiguo):
			msgPassAntiguoError = "El password no es correcto"
			errorVal = True
		if not passRe.match(password):
			msgPassError = "El nuevo password no es correcto"
			errorVal = True
		if not password == passwordRep:
			msgPass2Error = "Los passwords no coinciden"
			errorVal = True

		if not errorVal:
			nusersnombre = Usuarios.query(Usuarios.name==nombre, Usuarios.email!=email).count()
			if (nusersnombre==1):
				msgUserError = "Ya existe un usuario con ese nombre"
				errorVal = True
			else:
				existeUsuario = Usuarios.query(Usuarios.email==email, Usuarios.activo==True).count()
				if (existeUsuario==1):
					users = Usuarios.query(Usuarios.email==email)
					for user in users:
						salt = user.salero
						pass_bbdd = user.password
					
					pass_antiguo = hashlib.sha512(passwordAntiguo + salt).hexdigest()
					pass_nuevo = hashlib.sha512(password + salt).hexdigest()
					if not pass_bbdd==pass_antiguo:
						msgPassAntiguoError = "El password antiguo es distinto al almacenado"
						errorVal = True
					elif pass_nuevo==pass_antiguo:
						msgPassError = "El password nuevo coincide con el antiguo"
						errorVal = True
					else:
						#Aqui hago el update
						users = Usuarios.query(Usuarios.email==email)
						for l in users.fetch(limit = 1):
							l.name = nombre
							salt = uuid.uuid4().hex
							l.salero = salt
							hashed_password = hashlib.sha512(password + salt).hexdigest()
							l.password = hashed_password
							l.put()
							self.session['usuariologeando'] = email
							registrado = "1"
							self.session['registrado'] = registrado
							msgCorrecto = "FELICIDADES! "  + nombre + ", tus datos han sido modificados correctamente"
							#token = generate_confirmation_token(email)

				else:
					msgUserError = "Ha ocurrido un error. Usted no puede modificar sus datos"
					errorVal = True

		template_values = { 'idioma': 'es',
							'username': nombre,
						   'passwordAntiguo': passwordAntiguo,
							'password': password,
							'passwordRep': passwordRep,
							'email': email,
						   'msgRellene': 'Rellene los campos, por favor:',
						   'msgNomUser': 'Nombre de usuario',
						   'msgPass': 'Password',
						   'msgPassRep': 'Repetir password',
						   'msgEmail': 'Email',
						   'msgButEnviar': 'Enviar',
						   'msgHola': 'Hola',
						  'msgDatosOK': 'Tus datos son correctos',
						  'msgNomUserE': msgUserError,
						  'msgPassE': msgPassError,
						   'msgPassRepE': msgPass2Error,
						   'msgPassAntiguoError': msgPassAntiguoError,
						   'msgCorrecto': msgCorrecto,
						  'registrado': registrado}
		
		if errorVal:
			template = JINJA_ENVIRONMENT.get_template('modificarusuario.html')
		else:
			template = JINJA_ENVIRONMENT.get_template('tareaseis.html')
		
		self.response.write(template.render(template_values))

#@user_blueprint.route('/confirm/<token>')
#@login_required
#def confirm_email(token):
#	try:
#		email = confirm_token(token)
#	except:
#		flash('The confirmation link is invalid or has expired.', 'danger')
#	user = User.query.filter_by(email=email).first_or_404()
#	if user.confirmed:
#		flash('Account already confirmed. Please login.', 'success')
#	else:
#		user.confirmed = True
#		user.confirmed_on = datetime.datetime.now()
#		db.session.add(user)
#		db.session.commit()
#		flash('You have confirmed your account. Thanks!', 'success')
#	return redirect(url_for('main.home'))


app = webapp2.WSGIApplication([
    ('/', MainHandler),
		('/es', MainHandlerEs),
		('/en', MainHandlerEn),
		('/registro', Registrarse),
		('/registroes', RegistrarseEs),
		('/registroen', RegistrarseEn),
		('/verusuarios', VerUsuarios),
		('/verusuarioses', VerUsuariosEs),
		('/verusuariosen', VerUsuariosEn),
		('/validaremail', ValidarEmail),
		('/datos', Geolocalizacion),
		('/mapa', Mostrarmapa),
		('/autenticacion', Autenticacion),
		('/accesologin', AccesoLogin),
		('/validaremail2', ValidarEmail2),
		('/registroes2', RegistrarseEs2),
		('/login', Login),
		('/logout', Logout),
		('/addfoto', AddFoto),
		('/verfotos', VerFotos),
		('/serve/([^/]+)?', ServeHandler),
		('/modificarusuario', ModificarUsuario),
], config=session_module.config, debug=True,)