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
[webdev.andreasnicklaus.de](https://webdev.andreasnicklaus.de)

# Ungeschützte Architektur
![h:500 center](images/architecture_01.png)
# Ungeschützte Architektur
![h:500 center](images/architecture_02.png)
# Ungeschützte Architektur
![h:500 center](images/architecture_03.png)
# Ungeschützte Architektur
![h:500 center](images/architecture_04.png)
# Geschützte Datenbankstruktur
![h:500 center](images/architecture_05.png)

# Beispiel Twitter

Welche Arten von schlechten Inputs können wir erfahren?

```json
{
  "authorId" : "ElonMusksUserId",
  "content" : "Mark Zuckerberg is a great business man.",
  "creationTime": "2024-01-12T18:13:38.699Z"
}
```

# Beispiel Twitter
Schlechte Inputs

```json
{
  "authorId" : "iReallyAmElonMusk",
  "content" : "Mark Zuckerberg $§%&/&",
  "creationTime": "2024-01-12T18:13:38.699Z"
}
```
```json
{
  "content" : 123456,
  "creationTime": "1603-01-01T00:00:00.000Z"
}
```

# SQL Injection
```json
{
  "authorId" : "ElonMusksUserId'; DELETE * from Users; COMMIT;",
  "content" : "123456"
}
```
```sql
SELECT * from Users where id='ElonMusksUserId'; DELETE * from Users; COMMIT;'
```

# Schlechte Inputs

- Felder nicht gefüllt
- Felder nicht vorhanden
- Felder haben nicht den richtigen Typ
- Inhalt ist logisch nicht richtig
- Inhalt ist nicht erlaubt

# Inputvalidierung mit JOI

```js
const Joi = require('joi')

const myTwitterPostSchema = Joi.object({
  authorId: Joi.string().alphanum().required(),
  content: Joi.string().min(1).required()
})

const data = {
  authorId: "097151d159a0467ea3b45ec37abf771c",
  content: "Twitter was lame. I love X! <3"
}

const result = myTwitterPostSchema.validate(data)
if (result.error) console.error(result.error.message)
```

# Weitere Validierungsmöglichkeiten

[https://github.com/hapijs/joi/blob/v14.3.1/API.md](https://github.com/hapijs/joi/blob/v17.11.0/API.md)

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

# Beispiel für Einbindung an Express-Server
```js
app.post('/post', (req, res, next) => {
  const body = req.body
  const myTwitterPostSchema = Joi.object({
    authorId: Joi.string().alphanum().required(),
    content: Joi.string().min(1).required()
  })
  const result = myTwitterPostSchema.validate(body) 
  
  if (!result.error) { 
    res.status(422).json({ 
      message: 'Invalid request, error: ' + error.message, 
      data: body
    }) 
  } else { 
    createPost(data).then((createdPost) => {
      res.json({ message: 'Post created', data: createdPost }) 
    })
  } 
})
```

# Beispiel für Einbindung als Express-Middleware
```js
validateSchema = function (schema = null, property = null) {
  function middleware(req, res, next) {
    if (!JOI_ENABLED) return next()
    else {
      const { value, error } = schema.validate(req[property])

      if (error) {
        next(error);
        return;
      }
      else next()
    }
  }

  return middleware
}

app.post('/post', validateSchema(myTwitterPostSchema, "body"), => {
  ...
})
```

# Geschützter Backend-Server
![h:500 center](images/architecture_06.png)

## Was denkt ihr?

1. Ist das einfach?
2. Ist das effektiv?
3. Welche Problemen ergeben sich?