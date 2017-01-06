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

from google.appengine.api import users
from google.appengine.ext import ndb
from google.appengine.api import images
from base64 import b64encode

import json
import jinja2
import webapp2

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
		
		self.response.out.write("%s,%s"%(lat,lng))

class Autenticacion(webapp2.RequestHandler):
	def get(self):
		template_values = {}
		template = JINJA_ENVIRONMENT.get_template('autenticacion.html')
		self.response.write(template.render(template_values))

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
		('/accesologin', ValidarEmail),
		('/sss', ValidarEmail),
], debug=True)