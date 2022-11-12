#!/usr/bin/env python

import asyncio
import time
import tornado.httpserver
import tornado.ioloop
import tornado.web


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            ("/", UploadHandler)
        ]
        tornado.web.Application.__init__(self, handlers)


class UploadHandler(tornado.web.RequestHandler):
    def data_received(self, chunk):
        pass

    def set_default_headers(self):
        pass

    def post(self):
        for _, files in self.request.files.items():
            for file in files:
                filename = f"{time.time()}_{file['filename']}"
                with open(filename, "wb") as f:
                    f.write(bytearray(file["body"]))
                    f.close()
                print(
                    "File received.\n"
                    f"Filename: {file['filename']}\n"
                    f"Content type: {file['content_type']}\n"
                )


async def main():
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(8888)
    print("HTTP server started. Awaiting files.\n")
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
