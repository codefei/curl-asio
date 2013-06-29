/*
 * Copyright (c) 2013, Thomas Bluemel
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 * 
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 * 
 *     * Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef CURL_ASIO__HPP
#define CURL_ASIO__HPP

#include <map>
#include <set>
#include <list>
#include <cassert>

#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/bind.hpp>
#include <boost/function.hpp>

#include <sys/socket.h>
#include <curl/curl.h>

#ifdef CURL_ASIO_DEBUG
#include <cstdarg>
#define CURL_ASIO_LOGSCOPE(func,ptr) log_scope __log(func,ptr)
#define CURL_ASIO_LOG(fmt,...) log::print(__FILE__, __LINE__, log::format(fmt,##__VA_ARGS__))
#else
#define CURL_ASIO_LOGSCOPE(func,ptr)
#define CURL_ASIO_LOG(fmt,...)
#endif

#if defined(BOOST_MSVC) && (BOOST_MSVC >= 1400) \
  && (!defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600) \
  && !defined(BOOST_ASIO_ENABLE_CANCELIO)
#define __CURL_ASIO_CANCEL_WORKAROUND
#endif

class curl_asio
{
    class implementation;
    class socketinfo;
    
#ifdef CURL_ASIO_DEBUG
    class log
    { 
    public:
        static inline void print(const char *file, int lineno, const std::string &line)
        {
            printf("%s%s:%d: %s\n", indent().c_str(), file, lineno, line.c_str());
        }
        
        static inline void print(const std::string &line)
        {
            printf("%s%s\n", indent().c_str(), line.c_str());
        }
        
        static inline std::string format(const char *fmt, ...) __attribute__((format(printf, 1, 2)))
        {
            std::vector<char> buf;
            while (1)
            {
                va_list ap;
                va_start(ap, fmt);
                int n = vsnprintf(&buf[0], buf.capacity(), fmt, ap);
                va_end(ap);
                if (n < 0)
                    return std::string();
                
                if ((std::vector<char>::size_type)n >= buf.capacity())
                    buf.reserve(n + 1);
                else
                    return std::string(&buf[0], buf.capacity() - 1);
            }
            
            return std::string();
        }
        
        static inline std::string indent()
        {
            return std::string(indent_, '\t');
        }
        
    protected:
        static unsigned int indent_;
    };

    class log_scope: public log
    {
    public:
        log_scope(const std::string& func, void* ptr)
            : func_(func),
              ptr_(ptr)
        {
            print(format("---> %s() @ %p", func_.c_str(), ptr_));
            ++indent_;
        }
        
        ~log_scope()
        {
            --indent_;
            print(format("<--- %s() @ %p", func_.c_str(), ptr_));
        }
        
    private:
        const std::string func_;
        void* ptr_;
    };
#endif
    
    class callback_protector
    {
    public:
        callback_protector(unsigned int& counter)
            : counter_(counter)
        {
            counter_++;
        }
        
        ~callback_protector()
        {
            counter_--;
        }
        
    private:
        unsigned int& counter_;
    };
    
public:
    class transfer;
    
    explicit curl_asio(boost::asio::io_service& io)
        : impl_(implementation::create(io))
    {
    }
    
    virtual ~curl_asio()
    {
        impl_->terminate();
    }
    
    boost::shared_ptr<transfer> create_transfer() const
    {
        boost::shared_ptr<transfer> trans(new transfer(impl_));
        if (trans->init())
            return trans;
        return boost::shared_ptr<transfer>();
    }
    
    struct data_action
    {
        typedef enum
        {
            success,
            pause,
            abort
        } type;
    };
    
    struct header_action
    {
        typedef enum
        {
            success,
            abort
        } type;
    };
    
    class transfer: public boost::enable_shared_from_this<transfer>,
                    private boost::noncopyable
    {
    public:
        class info;
        
        typedef boost::function<data_action::type(const boost::asio::const_buffer&)> data_read_handler;
        typedef boost::function<data_action::type(boost::asio::mutable_buffer&)> data_write_handler;
        typedef boost::function<header_action::type(const std::string &line)> header_handler;
        typedef boost::function<void(const info&,CURLcode)> done_handler;
        
        struct options
        {
            long protocols;
            long max_redirs;
            long redir_protocols;
            bool fail_on_error;
            bool follow_location;
            bool auto_referer;
            bool http_proxy_tunnel;
            std::string proxy;
            std::string no_proxy;
            std::string proxy_username;
            std::string proxy_password;
            long proxy_port;
            long proxy_type;
            bool accept_all_supported_encodings;
            std::string accept_encoding;
            std::string referer;
            std::string useragent;
            std::list<std::string> http_header;
            std::string interface;
            
            options()
                : protocols(CURLPROTO_ALL),
                  max_redirs(-1),
                  redir_protocols(CURLPROTO_ALL & ~(CURLPROTO_FILE|CURLPROTO_SCP)),
                  fail_on_error(false),
                  follow_location(false),
                  auto_referer(false),
                  http_proxy_tunnel(false),
                  proxy_port(1080),
                  proxy_type(CURLPROXY_HTTP),
                  accept_all_supported_encodings(true)
            {
            }
        };
        
        class info: public boost::noncopyable
        {
        public:
            class timeinfo
            {
            public:
                double total;
                double namelookup;
                double connect;
                double appconnect;
                double pretransfer;
                double starttransfer;
                double redirect;
                
            private:
                friend class info;
                
                timeinfo(const info &i)
                {
                    if (!i.get_info(CURLINFO_TOTAL_TIME, total))
                        total = 0.0;
                    if (!i.get_info(CURLINFO_NAMELOOKUP_TIME, namelookup))
                        namelookup = 0.0;
                    if (!i.get_info(CURLINFO_CONNECT_TIME, connect))
                        connect = 0.0;
                    if (!i.get_info(CURLINFO_APPCONNECT_TIME, appconnect))
                        appconnect = 0.0;
                    if (!i.get_info(CURLINFO_PRETRANSFER_TIME, pretransfer))
                        pretransfer = 0.0;
                    if (!i.get_info(CURLINFO_STARTTRANSFER_TIME, starttransfer))
                        starttransfer = 0.0;
                    if (!i.get_info(CURLINFO_REDIRECT_TIME, redirect))
                        redirect = 0.0;
                }
            };
            
            std::string effective_url() const
            {
                std::string ret;
                get_info(CURLINFO_EFFECTIVE_URL, ret);
                return ret;
            }
            
            long response_code() const
            {
                long ret = 0;
                get_info(CURLINFO_RESPONSE_CODE, ret);
                return ret;
            }
            
            long http_connect_code() const
            {
                long ret = 0;
                get_info(CURLINFO_HTTP_CONNECTCODE, ret);
                return ret;
            }
            
            const timeinfo times() const
            {
                return timeinfo(*this);
            }
            
            long redirect_count() const
            {
                long ret = 0;
                get_info(CURLINFO_REDIRECT_COUNT, ret);
                return ret;
            }
            
            std::string redirect_url() const
            {
                std::string ret;
                get_info(CURLINFO_REDIRECT_URL, ret);
                return ret;
            }
            
        private:
            friend class transfer;
            friend class timeinfo;
            
            info(CURL*& handle)
                : handle_(handle)
            {
            }
            
            bool get_info(CURLINFO option, std::string &val) const
            {
                const char *str = NULL;
                CURLcode rc = curl_easy_getinfo(handle_, option, &str);
                if (rc == CURLE_OK)
                {
                    if (str)
                        val = str;
                    else
                        val.clear();
                    return true;
                }
                
                return false;
            }
            
            bool get_info(CURLINFO option, long &val) const
            {
                return curl_easy_getinfo(handle_, option, &val) == CURLE_OK;
            }
            
            bool get_info(CURLINFO option, double &val) const
            {
                return curl_easy_getinfo(handle_, option, &val) == CURLE_OK;
            }
            
            CURL*& handle_;
        };
        
        virtual ~transfer()
        {
            CURL_ASIO_LOGSCOPE("transfer::~transfer", this);
            if (handle_)
                curl_easy_cleanup(handle_);
            if (httpheader_)
                curl_slist_free_all(httpheader_);
        }
        
        const std::string& url;
        options opt;
        done_handler on_done;
        data_read_handler on_data_read;
        data_write_handler on_data_write;
        header_handler on_header;
        
        bool start(const std::string &uri)
        {
            if (running_ || !impl_ || callback_recursions_ > 0)
                return false;
            
            if (!init())
                return false;
            
            if (!setup(uri))
                return false;
            
            if (impl_->add_transfer(shared_from_this()))
            {
                running_ = true;
                return true;
            }
            
            return false;
        }
        
        bool stop()
        {
            if (!running_ || !impl_)
                return false;
            
            if (callback_recursions_ > 0)
            {
                running_ = false;
                return true;
            }
            
            if (impl_->remove_transfer(shared_from_this()))
            {
                running_ = false;
                return true;
            }
            
            return false;
        }
        
        bool running() const { return running_; }
        
    private:
        friend class curl_asio;
        friend class socketinfo;
        friend class implementation;
        
        boost::shared_ptr<implementation> impl_;
        unsigned int callback_recursions_;
        CURL* handle_;
        curl_slist *httpheader_;
        bool running_;
        std::string url_;
        boost::shared_ptr<transfer> lock_;
        
        static inline boost::shared_ptr<transfer> from_easy(CURL *easy)
        {
            void *trans;
            CURLcode rc = curl_easy_getinfo(easy, CURLINFO_PRIVATE, &trans);
            if (rc == CURLE_OK && trans)
                return static_cast<transfer*>(trans)->shared_from_this();
            return boost::shared_ptr<transfer>();
        }
        
        static inline boost::shared_ptr<transfer> from_ptr(void *ptr)
        {
            return static_cast<transfer*>(ptr)->shared_from_this();
        }
        
        transfer(boost::shared_ptr<implementation> impl)
            : url(url_),
              impl_(impl),
              callback_recursions_(0),
              handle_(NULL),
              httpheader_(NULL),
              running_(false)
        {
            CURL_ASIO_LOGSCOPE("transfer::transfer", this);
        }
        
        bool setup(const std::string &uri)
        {
            curl_easy_setopt(handle_, CURLOPT_URL, uri.c_str());
            
            curl_easy_setopt(handle_, CURLOPT_PROTOCOLS, opt.protocols);
            curl_easy_setopt(handle_, CURLOPT_MAXREDIRS, opt.max_redirs);
            curl_easy_setopt(handle_, CURLOPT_REDIR_PROTOCOLS, opt.redir_protocols);
            curl_easy_setopt(handle_, CURLOPT_FAILONERROR, opt.fail_on_error ? 1l : 0l);
            curl_easy_setopt(handle_, CURLOPT_FOLLOWLOCATION, opt.follow_location ? 1l : 0l);
            curl_easy_setopt(handle_, CURLOPT_AUTOREFERER, opt.auto_referer ? 1l : 0l);
            curl_easy_setopt(handle_, CURLOPT_HTTPPROXYTUNNEL, opt.http_proxy_tunnel ? 1l : 0l);
            if (!opt.proxy.empty())
                curl_easy_setopt(handle_, CURLOPT_PROXY, opt.proxy.c_str());
            if (!opt.no_proxy.empty())
                curl_easy_setopt(handle_, CURLOPT_NOPROXY, opt.no_proxy.c_str());
            if (!opt.proxy_username.empty() || !opt.proxy_password.empty())
            {
                curl_easy_setopt(handle_, CURLOPT_PROXYUSERNAME, opt.proxy_username.c_str());
                curl_easy_setopt(handle_, CURLOPT_PROXYPASSWORD, opt.proxy_password.c_str());
            }
            curl_easy_setopt(handle_, CURLOPT_PROXYPORT, opt.proxy_port);
            curl_easy_setopt(handle_, CURLOPT_PROXYTYPE, opt.proxy_type);
            if (opt.accept_all_supported_encodings)
                curl_easy_setopt(handle_, CURLOPT_ACCEPT_ENCODING, "");
            else
                curl_easy_setopt(handle_, CURLOPT_ACCEPT_ENCODING, opt.accept_encoding.empty() ? NULL : opt.accept_encoding.c_str());
            if (!opt.referer.empty())
                curl_easy_setopt(handle_, CURLOPT_REFERER, opt.referer.c_str());
            if (!opt.useragent.empty())
                curl_easy_setopt(handle_, CURLOPT_USERAGENT, opt.useragent.c_str());
            if (!opt.http_header.empty())
            {
                for (std::list<std::string>::const_iterator it(opt.http_header.begin()); it != opt.http_header.end(); ++it)
                {
                    curl_slist *new_list = curl_slist_append(httpheader_, it->c_str());
                    if (!new_list)
                        return false;
                    httpheader_ = new_list;
                }
                
                curl_easy_setopt(handle_, CURLOPT_HTTPHEADER, httpheader_);
            }
            
            if (!opt.interface.empty())
                curl_easy_setopt(handle_, CURLOPT_INTERFACE, ("if!" + opt.interface).c_str());
            
            curl_easy_setopt(handle_, CURLOPT_WRITEFUNCTION, curl_write_function);
            curl_easy_setopt(handle_, CURLOPT_WRITEDATA, this);
            
            curl_easy_setopt(handle_, CURLOPT_READFUNCTION, curl_read_function);
            curl_easy_setopt(handle_, CURLOPT_READDATA, this);
            
            curl_easy_setopt(handle_, CURLOPT_HEADERFUNCTION, curl_header_function);
            curl_easy_setopt(handle_, CURLOPT_HEADERDATA, this);
            
            url_ = uri;
            return true;
        }
        
        bool init()
        {
            CURL_ASIO_LOGSCOPE("transfer::init", this);
            
            if (handle_)
                curl_easy_reset(handle_);
            else
            {
                handle_ = curl_easy_init();
                if (!handle_)
                    return false;
            }
            
            if (httpheader_)
            {
                curl_slist_free_all(httpheader_);
                httpheader_ = NULL;
            }
            
            curl_easy_setopt(handle_, CURLOPT_PRIVATE, this);
            curl_easy_setopt(handle_, CURLOPT_NOSIGNAL, 1l);
            return true;
        }
        
        void terminate()
        {
            impl_.reset();
        }
        
        void lock() { lock_ = shared_from_this(); }
        void unlock() { lock_.reset(); }
        
        void handle_done(CURLcode result)
        {
            CURL_ASIO_LOG("transfer::handle_done: result=%d", result);
            if (on_done)
                on_done(info(handle_), result);
            running_ = false;
        }
        
        size_t write_function(char *ptr, size_t size)
        {
            if (impl_ && on_data_read)
            {
                callback_protector protector(callback_recursions_);
                data_action::type action = on_data_read(boost::asio::const_buffer(ptr, size));
                
                if (!running_)
                    return 0;
                
                switch (action)
                {
                    case data_action::success:
                        return size;
                    case data_action::pause:
                        return CURL_WRITEFUNC_PAUSE;
                    case data_action::abort:
                    default:
                        break;
                }
            }
            
            return 0;
        }
        
        static inline size_t curl_write_function(char *ptr, size_t size, size_t nmemb, void *userdata)
        {
            CURL_ASIO_LOGSCOPE("transfer::curl_write_function", userdata);
            return from_ptr(userdata)->write_function(ptr, size * nmemb);
        }
        
        size_t read_function(void *ptr, size_t size)
        {
            if (impl_ && on_data_write)
            {
                callback_protector protector(callback_recursions_);
                boost::asio::mutable_buffer buf(ptr, size);
                data_action::type action = on_data_write(buf);
                
                if (!running_)
                    return CURL_READFUNC_ABORT;
                
                switch (action)
                {
                    case data_action::success:
                        return size - boost::asio::buffer_size(buf);
                    case data_action::pause:
                        return CURL_READFUNC_PAUSE;
                    case data_action::abort:
                    default:
                        break;
                }
            }
            
            return CURL_READFUNC_ABORT;
        }
        
        static inline size_t curl_read_function(void *ptr, size_t size, size_t nmemb, void *userdata)
        {
            CURL_ASIO_LOGSCOPE("transfer::curl_read_function", userdata);
            return from_ptr(userdata)->read_function(ptr, size * nmemb);
        }
        
        size_t header_function(const char *ptr, size_t size)
        {
            if (impl_)
            {
                if (on_header)
                {
                    callback_protector protector(callback_recursions_);
                    header_action::type action = on_header(std::string(ptr, size));
                    
                    if (!running_)
                        return 0;
                    
                    switch (action)
                    {
                        case header_action::success:
                            return size;
                        case header_action::abort:
                        default:
                            break;
                    }
                }
                else
                    return size;
            }
            
            return 0;
        }
        
        static inline size_t curl_header_function(void *ptr, size_t size, size_t nmemb, void *userdata)
        {
            CURL_ASIO_LOGSCOPE("transfer::curl_header_function", userdata);
            return from_ptr(userdata)->header_function(static_cast<const char*>(ptr), size * nmemb);
        }
    };
    
private:
    boost::shared_ptr<implementation> impl_;
    
    class socketinfo: public boost::enable_shared_from_this<socketinfo>,
                      private boost::noncopyable
    {
    public:
        static inline boost::shared_ptr<socketinfo> from_ptr(void *ptr)
        {
            socketinfo *info = static_cast<socketinfo*>(ptr);
            return info ? info->shared_from_this() : boost::shared_ptr<socketinfo>();
        }
        
        static inline boost::shared_ptr<socketinfo> create(boost::asio::io_service &io, curl_socket_t s)
        {
            int type;
            struct sockaddr sa;
            socklen_t len;
            
            len = sizeof(type);
            if (::getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &len) < 0)
                return boost::shared_ptr<socketinfo>();
            
            len = sizeof(sa);
            if (::getsockname(s, &sa, &len) < 0)
                return boost::shared_ptr<socketinfo>();
            
            if (type == SOCK_STREAM)
            {
                if (sa.sa_family == AF_INET)
                    return boost::shared_ptr<socketinfo>(new tcpsocketinfo(io, boost::asio::ip::tcp::v4(), s));
                else if (sa.sa_family == AF_INET6)
                    return boost::shared_ptr<socketinfo>(new tcpsocketinfo(io, boost::asio::ip::tcp::v6(), s));
            }
            else if (type == SOCK_DGRAM)
            {
                if (sa.sa_family == AF_INET)
                    return boost::shared_ptr<socketinfo>(new udpsocketinfo(io, boost::asio::ip::udp::v4(), s));
                else if (sa.sa_family == AF_INET6)
                    return boost::shared_ptr<socketinfo>(new udpsocketinfo(io, boost::asio::ip::udp::v6(), s));
            }
            
            return boost::shared_ptr<socketinfo>();
        }
        
        socketinfo()
            : requested_action_(CURL_POLL_NONE)
        {
        }
        
        typedef boost::function<void(const boost::system::error_code&,std::size_t)> WaitHandler;
        
        virtual void cancel() = 0;
        virtual void async_wait_read(WaitHandler handler) = 0;
        virtual void async_wait_write(WaitHandler handler) = 0;
        
        int requested_action() const { return requested_action_; }
        
        void set_requested_action(int action)
        {
            requested_action_ = action;
            cancel();
        }
        
        socketinfo *add()
        {
            lock_ = shared_from_this();
            return this;
        }
        
        void remove()
        {
            cancel();
            lock_.reset();
        }
        
    protected:
        int requested_action_;
        boost::shared_ptr<socketinfo> lock_;
        
        static inline curl_socket_t dup_handle(curl_socket_t s)
        {
#if defined(_WIN32) || defined(_WIN64)
            WSAPROTOCOL_INFO info;
            return ::WSADuplicateSocket(s, ::GetCurrentProcessId(), &info);
#else
            return ::dup(s);
#endif
        }
    };
    
    class tcpsocketinfo: public socketinfo
    {
    public:
        tcpsocketinfo(boost::asio::io_service &io, const boost::asio::ip::tcp &version, curl_socket_t s)
            : socketinfo(),
              sock_(new boost::asio::ip::tcp::socket(io))
#ifdef __CURL_ASIO_CANCEL_WORKAROUND
              , version_(version)
#endif
        {
            sock_->assign(version, dup_handle(s));
        }
        
        virtual void cancel()
        {
            CURL_ASIO_LOGSCOPE("tcpsocketinfo::cancel", this);
#ifdef __CURL_ASIO_CANCEL_WORKAROUND
            boost::shared_ptr<boost::asio::ip::tcp::socket> old(sock_);
            sock_.reset(new boost::asio::ip::tcp::socket(old->get_io_service()));
            sock_->assign(version_, dup_handle(old->native_handle()));
            old->close();
#else
            sock_->cancel();
#endif
        }
        
        virtual void async_wait_read(WaitHandler handler)
        {
            sock_->async_read_some(boost::asio::null_buffers(), handler);
        }
        
        virtual void async_wait_write(WaitHandler handler)
        {
            sock_->async_write_some(boost::asio::null_buffers(), handler);
        }
        
    private:
        boost::shared_ptr<boost::asio::ip::tcp::socket> sock_;
#ifdef __CURL_ASIO_CANCEL_WORKAROUND
        const boost::asio::ip::tcp version_;
#endif
    };
    
    class udpsocketinfo: public socketinfo
    {
    public:
        udpsocketinfo(boost::asio::io_service &io, const boost::asio::ip::udp &version, curl_socket_t s)
            : socketinfo(),
              sock_(new boost::asio::ip::udp::socket(io))
#ifdef __CURL_ASIO_CANCEL_WORKAROUND
              , version_(version)
#endif
        {
            sock_->assign(version, dup_handle(s));
        }
        
        virtual void cancel()
        {
#ifdef __CURL_ASIO_CANCEL_WORKAROUND
            boost::shared_ptr<boost::asio::ip::udp::socket> old(sock_);
            sock_.reset(new boost::asio::ip::udp::socket(old->get_io_service()));
            sock_->assign(version_, dup_handle(old->native_handle()));
            old->close();
#else
            sock_->cancel();
#endif
        }
        
        virtual void async_wait_read(WaitHandler handler)
        {
            sock_->async_receive(boost::asio::null_buffers(), handler);
        }
        
        virtual void async_wait_write(WaitHandler handler)
        {
            sock_->async_send(boost::asio::null_buffers(), handler);
        }
        
    private:
        boost::shared_ptr<boost::asio::ip::udp::socket> sock_;
#ifdef __CURL_ASIO_CANCEL_WORKAROUND
        const boost::asio::ip::udp version_;
#endif
    };
    
    class implementation: public boost::enable_shared_from_this<implementation>,
                          private boost::noncopyable
    {
        typedef std::map< curl_socket_t, boost::shared_ptr<socketinfo> > socketinfo_map_t;
        typedef std::set< boost::shared_ptr<transfer> > transfer_set_t;
        
    public:
        static inline boost::shared_ptr<implementation> create(boost::asio::io_service& io)
        {
            return boost::shared_ptr<implementation>(new implementation(io));
        }
        
        virtual ~implementation()
        {
            curl_multi_cleanup(curl_);
        }
        
        void terminate()
        {
            CURL_ASIO_LOGSCOPE("implementation::terminate", this);
            assert(!terminated_);
            terminated_ = true;
            
            timer_.cancel();
            
            for (socketinfo_map_t::const_iterator it(sockets_.begin()); it != sockets_.end(); ++it)
                it->second->remove();
            sockets_.clear();
            
            for (transfer_set_t::const_iterator it(transfers_.begin()); it != transfers_.end(); ++it)
                (*it)->terminate();
            transfers_.clear();
        }
        
        bool add_transfer(boost::shared_ptr<transfer> trans)
        {
            CURL_ASIO_LOGSCOPE("implementation::add_transfer", this);
            assert(trans->handle_);
            
            if (!terminated_)
            {
                CURLMcode rc = curl_multi_add_handle(curl_, trans->handle_);
                if (rc <= CURLM_OK)
                {
                    transfers_.insert(trans);
                    trans->lock();
                    return true;
                }
            }
            
            return false;
        }
        
        bool remove_transfer(boost::shared_ptr<transfer> trans)
        {
            CURLMcode rc = curl_multi_remove_handle(curl_, trans->handle_);
            if (rc <= CURLM_OK)
            {
                transfer_set_t::iterator it(transfers_.find(trans));
                if (it != transfers_.end())
                {
                    trans->unlock();
                    transfers_.erase(it);
                }
                return true;
            }
            
            return false;
        }
    
    private:
        friend class transfer;
        friend class socketinfo;
        
        boost::asio::deadline_timer timer_;
        unsigned int callback_recursions_;
        socketinfo_map_t sockets_;
        transfer_set_t transfers_;
        CURLM* curl_;
        int running_;
        bool terminated_;
        
        static inline boost::shared_ptr<implementation> from_ptr(void *ptr)
        {
            implementation *impl = static_cast<implementation*>(ptr);
            return impl->shared_from_this();
        }
        
        implementation(boost::asio::io_service& io)
            : timer_(io),
              callback_recursions_(0),
              running_(0),
              terminated_(false)
        {
            curl_ = curl_multi_init();
            assert(curl_);
            
            curl_multi_setopt(curl_, CURLMOPT_SOCKETFUNCTION, curl_socket_function);
            curl_multi_setopt(curl_, CURLMOPT_SOCKETDATA, this);
            curl_multi_setopt(curl_, CURLMOPT_TIMERFUNCTION, curl_timer_function);
            curl_multi_setopt(curl_, CURLMOPT_TIMERDATA, this);
        }
        
        void process_curl_messages()
        {
            int msgs;
            while (CURLMsg* msg = curl_multi_info_read(curl_, &msgs))
            {
                if (msg->msg == CURLMSG_DONE)
                {
                    boost::shared_ptr<transfer> trans(transfer::from_easy(msg->easy_handle));
                    assert(trans);
                    if (!remove_transfer(trans))
                    {
                        CURL_ASIO_LOG("Could not remove easy handle");
                    }
                    trans->handle_done(msg->data.result);
                }
            }
        }
        
        void async_wait(curl_socket_t s, int action, boost::shared_ptr<socketinfo> sock)
        {
            CURL_ASIO_LOG("implementation::async_wait(s=%d, action=%d) sock=%p requested_action=%d", s, action, sock.get(), sock->requested_action());
            int requested_action = sock->requested_action();
            if (requested_action != action || requested_action == CURL_POLL_INOUT || requested_action == CURL_POLL_NONE)
            {
                sock->cancel();
                action = requested_action;
            }
            
            if (action & CURL_POLL_IN)
                sock->async_wait_read(boost::bind(&implementation::async_wait_complete, shared_from_this(), boost::asio::placeholders::error, s, CURL_POLL_IN, sock));
            
            if (action & CURL_POLL_OUT)
                sock->async_wait_write(boost::bind(&implementation::async_wait_complete, shared_from_this(), boost::asio::placeholders::error, s, CURL_POLL_OUT, sock));
        }
        
        void async_wait_complete(const boost::system::error_code &err, curl_socket_t s, int action, boost::shared_ptr<socketinfo> sock)
        {
            CURL_ASIO_LOGSCOPE("implementation::async_wait_complete", this);
            if (!err)
            {
                callback_protector protector(callback_recursions_);
                
                CURL_ASIO_LOG("implementation::async_wait_complete(s=%d, action=%d)", s, action);
                CURLMcode rc = curl_multi_socket_action(curl_, s, action, &running_);
                if (rc <= CURLM_OK)
                {
                    process_curl_messages();
                    
                    if (running_ > 0)
                        async_wait(s, action, sock);
                    else
                        sock->cancel();
                }
            }
        }
        
        int socket_function(curl_socket_t s, int action, boost::shared_ptr<socketinfo> sock)
        {
            callback_protector protector(callback_recursions_);
            socketinfo_map_t::iterator it(sockets_.find(s));
            
            if (action == CURL_POLL_REMOVE)
            {
                if (sock)
                {
                    sock->remove();
                    curl_multi_assign(curl_, s, NULL);
                }
                
                if (it != sockets_.end())
                    sockets_.erase(it);
            }
            else
            {
                if (!sock)
                {
                    sock = socketinfo::create(timer_.get_io_service(), s);
                    assert(it == sockets_.end());
                }
                
                if (it == sockets_.end() && sock)
                {
                    curl_multi_assign(curl_, s, sock->add());
                    it = sockets_.insert(std::make_pair(s, sock)).first;
                }
                
                if (it != sockets_.end())
                {
                    it->second->set_requested_action(action);
                    async_wait(s, action, it->second);
                }
            }
            
            return 0;
        }
        
        static inline int curl_socket_function(CURL *, curl_socket_t s, int action, void *userp, void *socketp)
        {
            CURL_ASIO_LOGSCOPE("curl_socket_function", userp);
            CURL_ASIO_LOG("socket=%d, action=%d socketinfo=%p", s, action, socketp);
            return from_ptr(userp)->socket_function(s, action, socketinfo::from_ptr(socketp));
        }
        
        void timer_handler(const boost::system::error_code &err)
        {
            if (!err)
            {
                callback_protector protector(callback_recursions_);
                CURLMcode rc = curl_multi_socket_action(curl_, CURL_SOCKET_TIMEOUT, 0, &running_);
                if (rc <= CURLM_OK)
                    process_curl_messages();
            }
        }
        
        int timer_function(long timeout_ms)
        {
            timer_.cancel();
            
            if (timeout_ms > 0)
            {
                timer_.expires_from_now(boost::posix_time::milliseconds(timeout_ms));
                timer_.async_wait(boost::bind(&implementation::timer_handler, shared_from_this(), boost::asio::placeholders::error));
            }
            else
            {
                boost::system::error_code err;
                timer_handler(err);
            }
            
            return 0;
        }
        
        static inline int curl_timer_function(CURLM *, long timeout_ms, void *userp)
        {
            CURL_ASIO_LOGSCOPE("curl_timer_function", userp);
            return from_ptr(userp)->timer_function(timeout_ms);
        }
    };
};

#undef __CURL_ASIO_CANCEL_WORKAROUND

#endif

