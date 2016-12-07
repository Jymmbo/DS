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

from google.appengine.api import users
from google.appengine.ext import ndb

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
						   'msgButEnviar': 'Bidali',
						  'msgHola': 'Kaixo',
						  'msgDatosOK': 'Zure datuak ongi daude',
						  'msgNomUserE': 'Izena gaizki dago!',
						  'msgPassE': 'Pasahitza gaizki dago!',
						   'msgPassRepE': 'Pasahitzek ez dute bat egiten!',
						   'msgEmailE': 'Email-a gaizki dago!'}
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
						   'msgButEnviar': 'Enviar',
						  'msgHola': 'Hola',
						  'msgDatosOK': 'Tus datos son correctos',
						  'msgNomUserE': 'Nombre incorrecto!',
						  'msgPassE': 'Password incorrecto!',
						   'msgPassRepE': 'Password no coincide!',
						   'msgEmailE': 'Email incorrecto!'}
		template = JINJA_ENVIRONMENT.get_template('registro.html')
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
						   'msgButEnviar': 'Submit',
						  'msgHola': 'Hello',
						  'msgDatosOK': 'Your data are well',
						  'msgNomUserE': 'The name is incorrect!',
						  'msgPassE': 'The password is incorrect!',
						   'msgPassRepE': 'Passwords do not match!',
						   'msgEmailE': 'The emai is incorrect!'}
		template = JINJA_ENVIRONMENT.get_template('registro.html')
		self.response.write(template.render(template_values))

class Registrarse(webapp2.RequestHandler):
	def get(self):
		template_values = { }
		template = JINJA_ENVIRONMENT.get_template('registro.html')
		self.response.write(template.render(template_values))
	
	def post(self):
		template_values = { 'usuario': self.request.get('username') }
		template = JINJA_ENVIRONMENT.get_template('registrofeliz.html')
		self.response.write(template.render(template_values))
		
		
app = webapp2.WSGIApplication([
    ('/', MainHandler),
		('/es', MainHandlerEs),
		('/en', MainHandlerEn),
		('/registro', Registrarse),
], debug=True)