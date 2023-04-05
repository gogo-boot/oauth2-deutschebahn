### Getting started with OAuth2 in Go

Authentication usually is very important part in any application. You can always implement your own authentication system, but it
will require a lot of work, registration, forgot password form, etc. That's why OAuth2 was created, to allow user to log in using
one of the many accounts user already has.

In this video we'll create a simple web page with Google login using oauth2 Go package.

### Google Project, OAuth2 keys

First of all, let's create our Google OAuth2 keys.

- Go to [Google Cloud Platform](https://console.developers.google.com/)
- Create new project or use an existing one
- Go to Credentials
- Click "Create credentials"
- Choose "OAuth client ID"
- Add authorized redirect URL, in our case it will be `localhost:8080/callback`
- Get client id and client secret
- Save it in a safe place

### How OAuth2 works with Google

- Obtain OAuth 2.0 credentials from the Google API Console.
- Obtain an access token from the Google Authorization Server.
- Send the access token to an API.
- Refresh the access token, if necessary.

### Structure

We'll do everything in 1 main.go file, and register 3 URL handlers:

- /
- /login
- /callback

### Set Environment Variables

We save google client id and secret in env variables and only use os.Getenv in the code.

```
cp template.env test.env
# Set your client id / password. It is for IDE env Plugin. 
# you don't have to export environmentvariable manually. don't push it to git reop 
vi test.env
```

### Test it

```
go run main.go
```

### Conclusion

That's all what we need to do to integrate OAath2 with Google in Go. As you can see, it's only 70 lines of code.

Also, there is a nice package https://github.com/markbates/goth from Mark Bates which provides multi-provider authentications.

### License

It is copy from https://medium.com/@pliutau/getting-started-with-oauth2-in-go-2c9fae55d187