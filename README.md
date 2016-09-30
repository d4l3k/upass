# UPass Renewer
A service for doing UPass activations automatically.

![Screenshot](https://i.imgur.com/QzUc4lO.png)

## Running on Docker (port 8080)
```bash
docker run -v /tmp/foo:/data -p 8080:3000 -d --restart=always d4l3k/upass app -dir="/data"
```

## Running

```bash
$ git clone https://github.com/d4l3k/upass.git
$ cd upass
$ go get && go build
$ ./upass
2015/11/20 15:26:53 Listening on :3000
```

## Setting up encryption

To decrypt/generate the decryption key you need to go to `/decrypt.html` and
enter a password after every restart. If it succeeds you should see on of:

```
2015/11/20 15:26:44 Generating new key ./db.key...

or

2016/09/30 22:30:33 Loading key ./db.key...

```

## License
UPass Renewer is licensed under the MIT license.

Made by [Tristan Rice](https://fn.lc).
