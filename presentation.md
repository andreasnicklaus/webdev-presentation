---
marp: true
theme: rose-pine
headingDivider: 2
_class: lead
paginate: true
style: |
  .mermaid {
    background-color: transparent; border-color: transparent; width: max-content; margin: 0 auto;
  }
  img[alt~=center]{
    width: 100%;
    object-fit: contain;
    margin: 0 auto;
    background-color: transparent;
  }
---
<!-- _paginate: false -->
# Web-Development Backend

JOI und JWT - Server vor invalidem Input schützen
oder:
Wie mache ich den Server kaputt?
<br>
[webdev.andreasnicklaus.de](https://webdev.andreasnicklaus.de) - [:file_folder: PDF herunterladen](https://webdev.andreasnicklaus.de/joi_jwt.pdf)

<!-- Thema: Server vor invalidem Input schützen
oder Wie mache ich den Server kaputt?

[interaktive Session]
[Folien online verfügbar]
[PDF herunterladen]

[prüfungsrelevante Themen in den Folien im Gitrepo, großer Überlapp]
 -->

# Was haben wir bisher gemacht?
:white_check_mark: HTTP-Server mit Express
:white_check_mark: HTML-Rendering mit EJS
:white_check_mark: Datenbankanbindung mit MongoDB
:white_check_mark: Datenbankverwaltung mit Mongoose
:white_check_mark: 2-Way-Kommunikation mit Websockets
:white_square_button: ???
:white_square_button: ???

<!-- 
Zuerst ein Rückblick: Was haben wir im Semester bisher gemacht?

1. Mit Express HTTP-Server intialisieren und REST-Endpoints definieren
2. HTML-Rendering mit EJS, um HTML-Snippets zu generieren und auf einer Webseite einbinden
3. Anbindung an MongoDB mit dem mongodb NPM package
4. Datenbankschemata mit Mongoose erstellt
5. letzte Woche: 2-way Kommunikation mit Websockets, damit alle Kommunikationspartner Nachrichten initiieren können

2 Themen kommen heute dazu
 -->

# Ungeschützte Architektur
![h:500 center](https://andreasnicklaus.github.io/webdev-presentation/images/architecture_01.png)
<!-- 
Erste Architektur mit Express und MongoDB

1. Client, Web application, Browserfenster
2. Express-Server unabhängig von HTTP-Server, Websockets oder andere Kommunikation
3. MongoDB könnte jede andere Datenbank sein
 -->
# Ungeschützte Architektur
![h:500 center](https://andreasnicklaus.github.io/webdev-presentation/images/architecture_02.png)
<!-- 
Nachteile von dieser Architektur:

1. Müll als Inputdaten führt zum Verlust von Vertrauen in Daten, die vom Server kommen
2. Müll als Query-Daten führt zum Verlust in Daten in der Datenbank
 -->
# Ungeschützte Architektur
![h:500 center](https://andreasnicklaus.github.io/webdev-presentation/images/architecture_03.png)
<!--
Mehr noch:

Verlust von Kontrolle über die geschriebenen Daten
-> Datenbank wird komplett marode
-> Datenbank stürzt ab oder wird unbrauchbar
 -->
# Ungeschützte Architektur
![h:500 center](https://andreasnicklaus.github.io/webdev-presentation/images/architecture_04.png)
<!-- 
Infolgedessen kommt der Server auch in Stress, mit den Anfragen klar zu kommen.

Nach kurzer Zeit ist auch der Server nicht mehr erreichbar, weil er überfordert ist.
 -->
# Geschützte Datenbankstruktur
![h:500 center](https://andreasnicklaus.github.io/webdev-presentation/images/architecture_05.png)
<!--
Vor Weihnachten haben wir mit Mongoose definiert, wie Daten aussehen müssen, die in die Datenbank geschrieben werden.

Die Datenbank wird dadurch zumindest funktional abgesichert.

Dadurch wird das Vertrauen in die Daten, die von der Datenbank kommen, wieder hergestellt.

Der Server bleibt aber unsicher, weil auch Daten ankommen können, die nicht vorhergesehen werden.
 -->

# Beispiel Twitter

Welche Arten von schlechten Inputs können wir erfahren?
```json
{
  "authorId" : "ElonMusksUserId",
  "content" : "Mark Zuckerberg is a great business man.",
  "creationTime": 1705326917363
}
```

![h:200 center](images/Tweet.png)
<!-- 
Frage: Was für schlechte Inputs können wir erfahren?

Beispiel: Twitter/X
{
  "authorId" : "ElonMusksUserId",
  "content" : "Mark Zuckerberg is a great business man.",
  "creationTime": 1705326917363
} 

[Brainstorming]
- Unflätiger oder illegaler Inhalt
- Unlogischer Inhalt
- Fehlendes Feld / Leeres Feld
- Falsches Format
 -->

# Beispiel Twitter
Schlechte Inputs
```json
{
  "authorId" : "iReallyAmElonMusk",
  "content" : "Mark Zuckerberg $§%&/&",
  "creationTime": 000000001
}
```
```json
{
  "link": null,
  "content" : 123456,
  "creationTime": "1603-01-01T00:00:00.000Z",
}
```
<!--
- Unflätiger oder illegaler Inhalt
- Unlogischer Inhalt
- Fehlendes Feld / Leeres Feld
- Falsches Format
 -->

# SQL Injection
```json
{
  "authorId" : "ElonMusksUserId'; DELETE * from Users; COMMIT;",
  "content" : "123456",
  "creationTime": 1705326917363
}
```
```sql
SELECT * from Users where id='<user-input>'
```
```sql
SELECT * from Users where id='ElonMusksUserId'; DELETE * from Users; COMMIT;'
```
<!-- 
Häufige und relativ simple Atacke: SQL Injection

[Wer kennt SQL Injection?]
 -->

# Schlechte Inputs

- Felder nicht gefüllt
- Felder nicht vorhanden
- Felder haben nicht den richtigen Typ
- Inhalt ist logisch nicht richtig
- Inhalt ist nicht erlaubt
<!-- 
Wiederholung, was alles falsch laufen kann
 -->

# Inputvalidierung mit JOI
```js
const Joi = require('joi')

const myTwitterPostSchema = Joi.object({
  authorId: Joi.string().alphanum().required(),
  content: Joi.string().min(1).required(),
  creationTime: Joi.number().integer()
    .min(new Date().valueOf()-60000)
    .max(new Date().valueOf()).required()
})

const data = {
  authorId: "097151d159a0467ea3b45ec37abf771c",
  content: "Twitter was lame. I love X! <3"
}

const result = myTwitterPostSchema.validate(data)
if (result.error) console.error(result.error.message)
```
<!-- 
Lösung: Inputvalidierung mit JOI

1. NPM package 'joi'
2. Schema definieren mit Funktionen: Object
   1. String -> alphanumerisch -> required
   2. String -> Mindestlänge 1 -> required
   2. Number -> Integer -> Mindestwert: Jetzt - 1 Minute -> Maximalwert: Jetzt -> required
3. data
4. validierung mit `schema.validate(data)`
 -->

# Weitere Validierungsmöglichkeiten
```js
// Joi.object() beschreibt ein JS-Object
const schema = Joi.object({
  // Joi.string() beschreibt ein JS-String
    username: Joi.string().alphanum().min(3).max(30).required(),

    // .pattern() erlaubt eine Regular Expression
    password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')),

    // .ref() verweist auf ein anderes Schema
    repeat_password: Joi.ref('password'),

    // Array erlaubt mehrere optionale Typen 
    access_token: [Joi.string(), Joi.number()],

    // string.email() defniert den String als E-Mail-Adresse
    email: Joi.string().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } })
})
```
<!-- _footer: "[https://github.com/hapijs/joi/blob/v17.11.0/API.md](https://github.com/hapijs/joi/blob/v17.11.0/API.md)"
 -->
<!-- 
Viel mehr Funktionen für Validierung

- Password Regex Pattern: alphanumerisch, 3-30 Zeichen
- repeat_password: referenzieren eines Schemas mit Joi.ref()
- optionale Optionen, ob String oder Number, nicht required
- Für Datentypen gibt es Formate, z.B. email oder Integer

[Link für mehr Möglichkeiten]
 -->

# Beispiel für Einbindung an Express-Server
```js
app.post('/post', (req, res, next) => {
  const myTwitterPostSchema = Joi.object({
    authorId: Joi.string().alphanum().required(),
    content: Joi.string().min(1).required(),
    creationTime: Joi.number().integer()
      .min(new Date().valueOf()-60000).max(new Date().valueOf()).required()
  })
  const result = myTwitterPostSchema.validate(req.body) 
  
  if (!result.error) { 
    res.status(422).json({ 
      message: 'Invalid request, error: ' + error.message, 
      data: req.body
    }) 
  } else { 
    createPost(data).then((createdPost) => {
      res.json({ message: 'Post created', data: createdPost }) 
    })
  } 
})
```
<!-- 
Eingebunden in Express-Server

1. Schema definieren
2. Mit Request Body validieren
3. Bei Error 422, andernfalls createPost()

- Schema nicht wiederverwendbar
- Business-Logik vermischt mit Format-Logik
 -->

# Beispiel für Einbindung als Express-Middleware
```js
validateSchema = function (schema, property) {
  function middleware(req, res, next) {
    const { value, error } = schema.validate(req[property])

    if (error) {
      next(error);
      return;
    }
    else next()
  }

  return middleware
}

app.post('/post', validateSchema(myTwitterPostSchema, "body"), => {
  ...
})
```
<!-- 
Besser: Middlewares

validateschema(schema, property)

1. return middleware
2. middleware(req, res, next)
   1. validieren mit daten aus der Property vom Request
   2. Errorhandler, andernfalls Requesthandler

Parameter: Schema und Property des Requests (Body, Query, Params)

Alternativ Websocket-Message Middleware
 -->

# Geschützter Backend-Server
![h:500 center](https://andreasnicklaus.github.io/webdev-presentation/images/architecture_06.png)
<!-- 
Mit JOI den Server schützen

Input-Müll frühzeitig erkennen und Request nicht weiter bearbeiten
 -->

# Nutzung von JOI
:arrow_right: [Codebeispiel](https://gitlab.mi.hdm-stuttgart.de/fridtjof/web-development-backend/-/tree/master/examples/06-joi-jwt?ref_type=heads)

## Was denkt ihr?

1. Ist das einfach?
2. Ist das effektiv?
3. Welche Problemen ergeben sich?
<!-- 
[Umfrage]

[Developer-Experience]
[Wo & wofür werden Schemas definiert?]
[Updateverfahren: Wie oft muss ich definieren? Wie oft updaten?]

- Extra Rechenleistung
- Automatisierung
- Duplizierte Typdefinition an mehreren Orten
  - JOI
  - Mongoose
  - [Datenbank]

[Pause?]
Was geschrieben wird, aber nicht wer schreibt.
 -->

# Authentisierung falsch gemacht
```json
{
  "myId": "097151d159a0467ea3b45ec37abf771c",
  "posts": [
    {
      "content": "This is a funny tweet about spaghetti.",
      "creationTime": 1705326917363
    }
  ]
}
```
Ist das sicher?
<!-- 
Beispiel-Request-Body
[Viele Wege führen nach Rom]

Was ist falsch an dieser Art der Authentisierung?
-> myId könnte alles sein, selbst wenn es formal richtig ist

Andere Art von Sicherheit, nicht technisch

Insb. rechtlich wichtig nachzuweisen, wer wann wo was macht
 -->

# Authentisierung richtig gemacht

> The HTTP Authorization request header can be used to provide credentials that authenticate a user agent with a server, allowing access to a protected resource.

`Authorization: <auth-scheme> <authorization-parameters>`

Hier werden 2 Authentisierungsschemas vorgestellt, es gibt aber noch mehr:
1. Basic
2. Bearer

<!-- _footer: "[https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization)" -->
<!-- 
Authentisierung richtig gemacht

Richtig: Nicht im Request Body, sondern im Authorization Header
[Zitat über Nutzung des Authorization Headers]

Schema: Authorization: <auth-scheme> <authorization-parameters>

Heute 2 Authentisierungsschemata: Basic & Bearer
 -->

## Basic Authorization

`Authorization: Basic <base64('<username>:<password>')>`

- Authentisierungsschema: `Basic`
- Authentisierungsparameter besteht aus dem Base64-enkodiertem String `<username>:<password>`
- Oft genutzt mit `WWW-Authenticate`, z.B. beim [HdM Intranet](https://www.hdm-stuttgart.de/intranet)

<!--
_footer: "[https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization#basic](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization#basic)"
-->
<!-- 
Basic Authorization

Authorization: Basic <base64('<username>:<password>')>

WWW-Authenticate: Browser-Alert mit Nutzername und Passwort

[Beispiel https://www.hdm-stuttgart.de/intranet]
[Zeigen mit https://www.base64encode.org/]
 -->

## Basic Authorization
<div style="background-color: #ff4400aa; border: solid 6px #ff4400; padding: 10px 20px; margin: 10px 0; border-radius: 10px;">
  <span style="color: white;">Warnung: Base64-encoding kann einfach zum ursprünglichen Namen und Passwort dekodiert werden. Basic Authentisierung ist deshalb <b>vollständig unsicher</b>. HTTPS is immer empfohlen, wenn Authentisierung benutzt wird, aber besonders bei `Basic` Authentisierung.</span>
</div>

<!-- 
[Warnung]

Zeigen mit https://www.base64decode.org/
bWF4MTIzOnN1cGVyU3Rhcmtlc1Bhc3N3b3J0MTIz

Passwort und Nutzername sind einfach dekodierbar
 -->

## Bearer Authorization

`Authorization: Bearer <Token>`

- Authentisierungsschema: `Bearer`
- Authentisierungsparameter besteht aus einem `Token`, das der Client nie anfassen will und soll

Bearer Authentisierung erfordert, dass der Token vom Client nicht verändert werden kann

:arrow_right: JSON Web Tokens
<!-- 
Bearer Authorization

Authorization: Bearer <Token>

- Token ist frei definierbar
- Bearer bedeutet Träger, Aufbewahrer -> Ringebearer aus Herr der Ringe
- Bearer Authentisierung erfordert, dass der Token vom Client nicht verändert werden kann

Eine Methode, die diese Anforderungen erfüllt, sind JSON Web Tokens

[Pause?]
 -->

# Intermezzo: IDs

![center](https://andreasnicklaus.github.io/webdev-presentation/images/yt-id.png)

ID-Formate:
- Youtube: `xxxxx-xxxxx` alphanumerisch
- IG Reels: `xxxxxxxxxxx` alphanumerisch
- IG Stories: `0000000000000000000` numerisch
- Twitter/X: `0000000000000000000` numerisch
<!--
Intermezzo über Ids

Token-Idee Nutzer-Id, welche Probleme damit auftreten

- Youtube: 2 Gruppen an 5 alphanumerischen Zeichen
- Instagram Reels: 10 alphanumerische Zeichen
- Instagram Stories & Twitter Posts: 19 numerische Zeichen
-->

# Intermezzo: IDs
Beispiel Youtube: `https://www.youtube.com/watch?v=ElHFJ-8Hy6E`

Ein paar Fragen zur Auswahl des Formats:
- Welche ID wird als nächste vergeben? Sollte ich dieses Video aufrufen können?
- Wie viele Varianten gibt das Format her?
- Wie groß ist die Wahrscheinlichkeit, eine ID zu erraten?
<!-- 
Anekdote: Youtube-Video-Ids 
- Zu viele Videos
- Nächstes Video ist nächste Id, ggf. nicht öffentlich
- Hier 36^10 Varianten = 3 * 10^15 = 3 Billiarden
- Wahrscheinlichkeit 800 Mio. / 3 Billiarden = 2 / 10 Mio. = 0,00026%
 -->

# JSON Web Token (JWT)

Verschlüsselte Tokens zur Authentifizierung von JSON-Daten

1. Datenverschlüsselung: Daten werden geheim gehalten
2. Datenintegrität: Signierte Tokens

Online Token-Generator: [https://jwt.io/](https://jwt.io/)
<!-- 
Hier kommen JWTs ins Spiel

Verschlüsselte Tokens zur Authentifizierung von JSON-Daten

2 Features:

1. Datenverschlüsselung: Daten sind nicht lesbar
2. Datenintegrität: Daten werden nicht verändert. Durch Signatur sichergestellt.

Wir schauen uns an, wie JWTs funnktionieren.
 -->

# Aufbau eines JWT
`hhhhh.pppppppppppppppppppppp.ssssssssssss`

1. Header
2. Payload
3. Signature
<!-- 
3 Teile:

1. Header: In der Regel kurz, Metainformationen
2. Payload: Daten, die ich verschlüsseln will, z.B. Authentisierungsinformationen
3. Signature: Integrität von Header und Payload

Im Detail vorgestellt ->
 -->

## JWT Teil 1/3: Header
```json
{
  "typ": "JWT",
  "alg": "HS256"
}
```
wird Base64Url kodiert.
<!-- 
2 Teile im JSON:

1. Typ, hier meistens JWT
2. Algorithmus, zum Beispiel HMAC SHA256 oder RSA, für die Signatur

JSON-String wird Base64Url enkodiert.
 -->

## JWT Teil 2/3: Payload
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516171819
}
```
wird Base64Url kodiert.

- Properties des Payloads werden **Claim** genannt
- Registrierte Claims sind `sub` (Subject), `iss` (Issuer), `exp` (Expiration Time), `aud` (Audience, Array of Strings), `iat` (Issued at), `jti` (JWT Id), `nbf` (Not before)
- Neben Public Claims der JSON Web Token Claims Registry sind auch
**Private Claims** erlaubt **(Vorsicht vor Kollisionen)**
<!-- 
JSON ist theoretisch beliebig aufbaubar

- Properties im Payload werden Claim genannt
- Registrierte, sog. Public Claims, sind sub, iss, exp, aud, iat, jti, nbf
- Private Claims immernoch erlaubt

JSON-String wird Base64Url enkodiert.
 -->

## JWT Teil 3/3: Signature
```js
HMAC(Base64Url(header).Base64Url(payload), secret)
```

- Im einfachen Fall werden Header und Payload mit HMAC-Verschlüsselung (hash-base message auth code) symmetrisch verschlüsselt.
- Payload und Header werden dennoch unverschlüsselt verwendet.
<!--
Signatur ist Base64-encoded Header und Payload, HMAC-verschlüsselt

- HMAC: hash-base message auth code
- Hash-Funktionen sind one-way, man kann also nur nachweisen, dann der Body nicht verändert wurde
- Deshalb muss Header und Payload trotzdem unverschlüsselt versandt werden.

[Exkurs: Hash-Funktionen]

-> Secret müsste dem Client bekannt sein, praktisch nicht möglich

-> https://jwt.io/#debugger-io
[Rumspielen]
 -->

# Warum sind JWTs sicher?

- Header und Payload sind Base64-enkodiert :arrow_right: **Lesbar und veränderbar**
- Signatur enthält Secret, Header und Payload :arrow_right: **Änderungen sind nachweisbar**

<br>

- Änderungen sind nicht reversibel, das Original bleibt unbekannt.
- Keine sensiblen Daten sollten in JWTs verpackt werden.
<!-- 
- Base64 ist dekodierbar, also Payload lesbar und veränderbar
- Aber Änderungen sind nachweisbar, weil die Signatur dann nicht mehr zum Payload und Header passt

- Änderungen sind nicht reversibel
-> Also keine sensiblen Daten in JWTs verpacken!
 -->

# JWT mit RSA-Verschlüsselung
```js
const message =
  RSA_with_publicKey_of_receiver(Base64(Header)) + "." +
  RSA_with_publicKey_of_receiver(Base64(Payload))

const signature = RSA_with_privateKey_of_sender(message)
```
<!-- 
RSA-Verschlüsselung könnte Base64-Enkodierung und HMAC ersetzen

- nur Receiver kann Payload und Header lesen
- nur Sender kann Signatur schreiben
 -->

# Verwendung von JWTs im Client
```js
// Token wird vom letzten Request gespeichert, modifiziert und/oder generiert
const token = getOrGenerateToken()

fetch("http://example.com/path/",
  {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer ' + token
    },
    body: JSON.stringify({...data})
  }
)
```
<!-- 
Im Client JWT im Authorization-Header setzen

1. Token vom letzten Request gespeichert, modifiziert und/oder generiert
2. Authorization Header: 'Bearer ' + token
 -->

# Generierung von JWTs im Server
```js
const jwt = require('jsonwebtoken')

const SECRET = require('crypto').randomBytes(64).toString('hex')
// '09f26e402586e2faa8da4c98a35f1b20d6b033c6097befa8be3486a829587fe2f90a832bd
//  3ff9d42710a4da095a2ce285b009f0c3730cd9b8e1af3eb84df6611'

function generateAccessToken(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: '1800s' })
}

app.post('/path', (req, res) => {
  const token = generateAccessToken({ username: req.body.username })
  res.json(token)
})
```
<!-- 
Im Server generieren

1. NPM-package `jsonwebtokens`
2. Random Secret generieren
3. jwt.sign(payload, secret, public_claims)
4. Im Request handler
 -->

# JWT-Dekodierung
```js
app.post('/path', authenticateToken, (req, res) => {
  // handle request
})

//middleware for authentication
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader.split(' ')[1]
  if (token == null) return res.sendStatus(401)
  jwt.verify(token, SECRET, (err, user) => {
    if (err) 
      return res.sendStatus(403)
    req.user = user
    next()
  })
}
```
<!-- 
Besser in einer Middleware

1. req.headers['authorization']
2. token auslesen
3. nicht vorhanden: 401
4. andernfalls verifizieren
5. nicht valide: 403
6. andernfalls nächster Requesthandler
 -->

# Nutzung von JWTs
:arrow_right: [Codebeispiel](https://gitlab.mi.hdm-stuttgart.de/fridtjof/web-development-backend/-/tree/master/examples/06-joi-jwt?ref_type=heads)

# Was haben wir erreicht?
:white_check_mark: HTTP-Server mit Express
:white_check_mark: HTML-Rendering mit EJS
:white_check_mark: Datenbankanbindung mit MongoDB
:white_check_mark: Datenbankverwaltung mit Mongoose
:white_check_mark: 2-Way-Kommunikation mit Websockets
:white_check_mark: Inputvalidierung mit JOI
:white_check_mark: Authentisierung mit JSON Web Tokens
<!-- 
Jetzt dazugekommen:

1. Inputvalidierung
2. Authentisierung
 -->