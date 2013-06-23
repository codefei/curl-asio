curl-asio
=========

A libcurl c++ wrapper class for easy use with boost::asio.

Features
--------

* **Simplicity** - It is very easy to use.  It even uses boost::shared_ptr so you don't have to worry about memory management.  Just include curl_asio.hpp and you're good to go!
* **License** - curl_asio is is licensed under the terms of the BSD license.
* **c-ares** - It supports libcurl with c-ares enabled.

Example
-------
The following application uses curl_asio to download a file from the web and saves it into a file.
```c++
#include "curl_asio.hpp"
#include <iostream>
#include <fstream>

static curl_asio::data_action::type on_transfer_data_read(std::ofstream &out, const boost::asio::const_buffer& buffer)
{
    out.write(boost::asio::buffer_cast<const char*>(buffer), boost::asio::buffer_size(buffer));
    return curl_asio::data_action::success;
}

static void on_transfer_done(const std::string &url, std::ofstream &out, const std::string &file, CURLcode result)
{
    if (result == CURLE_OK)
    {
        out.close();
        
        std::cout << "Transfer of " << url << " completed successfully! Content saved to file " << file << std::endl;
        exit(0);
    }
    else
    {
        std::cerr << "Transfer of " << url << " failed with error " << result << std::endl;
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " URL FILE" << std::endl;
        return 1;
    }
    
    boost::asio::io_service io;
    curl_asio curl(io);
    boost::shared_ptr<curl_asio::transfer> transfer = curl.create_transfer();
    if (transfer)
    {
        std::ofstream out(argv[2]);
        transfer->opt.protocols = CURLPROTO_HTTP | CURLPROTO_HTTPS;
        transfer->opt.max_redirs = 5;
        transfer->opt.redir_protocols = CURLPROTO_HTTP | CURLPROTO_HTTPS;
        transfer->opt.follow_location = true;
        transfer->on_data_read = boost::bind(on_transfer_data_read, boost::ref(out), _1);
        transfer->on_done = boost::bind(on_transfer_done, boost::ref(transfer->url), boost::ref(out), argv[2], _1);
        if (transfer->start(argv[1]))
        {
            while (1)
                io.run();
        }
    }
    
    return 1;
}
```
