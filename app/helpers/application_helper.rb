module ApplicationHelper

    # Returns the full title on a per-page basis.
    def full_title(page_title = '')
        base_title = "OwnYourData"
        if page_title.empty?
            base_title
        else
            page_title + " | " + base_title
        end
    end

    def main_color(color)
        case color
        when "cyan"
            "#3DD4FF"
        when "purple"
            "#9751FF"
        when "green"
            "#44FF6C"
        when "yellow"
            "#FFFE50"
        else
            "#3DD4FF"
        end
    end

    def footer_color(color)
        case color
        when "cyan"
            "#8AE6FF"
        when "purple"
            "#C59EFF"
        when "green"
            "#91FFA9"
        when "yellow"
            "#FFFF9C"
        else
            "#8AE6FF"
        end
    end

    def select_color(color)
        case color
        when "cyan"
            "#1F6B80"
        when "purple"
            "#4B2980"
        when "green"
            "#228037"
        when "yellow"
            "#808028"
        else
            "#1F6B80"
        end
    end

    def str2ascii(value)
        # https://stackoverflow.com/questions/1268289/how-to-get-rid-of-non-ascii-characters-in-ruby
        replacements = { 
            'á' => "a", 
            'à' => "a", 
            'é' => "e", 
            'è' => "e", 
            'ë' => 'e', 
            'í' => "i", 
            'ì' => "i", 
            'ú' => "u", 
            'ù' => "u", 
            "Ä" => "Ae", 
            "a" => "ae", 
            "Ö" => "Oe", 
            "ö" => "oe", 
            "Ü" => "Ue", 
            "ü" => "ue", 
            "ß" => "ss" }
        encoding_options = {
          :invalid   => :replace,     # Replace invalid byte sequences
          :replace => "",             # Use a blank for those replacements
          :universal_newline => true, # Always break lines with \n
          # For any character that isn't defined in ASCII, run this
          # code to find out how to replace it
          :fallback => lambda { |char|
            # If no replacement is specified, use an empty string
            replacements.fetch(char, "")
          },
      }
      return value.encode(Encoding.find('ASCII'), encoding_options)
    end

# Basic functions to access a PDS ====================
    def getCepsToken(ceps_url, ceps_user, ceps_password)
        auth_url = ceps_url.to_s + "/ceps/app_token"
        begin
            post_response = HTTParty.post(auth_url, 
                headers: { 'Content-Type' => 'application/json' },
                body: { user_id: ceps_user, 
                        password: ceps_password, 
                        app_name: "eu.oyd.tallyzoo" }.to_json )
        rescue => ex
            post_response = nil
        end
        if post_response.nil?
            nil
        else
            JSON(post_response.parsed_response.to_s)["app_token"].to_s rescue nil
        end
    end

    def getPersoniumToken(url, user, password)
        require 'net/http'
        require 'uri'

        response = nil
        begin
            uri = URI.parse(url + "/__token")
            request = Net::HTTP::Post.new(uri)
            request.content_type = "application/x-www-form-urlencoded"
            request["Accept"] = "application/json"
            request.set_form_data(
              "grant_type" => "password",
              "p_cookie" => "false",
              "password" => password,
              "username" => user,
            )

            req_options = {
              use_ssl: uri.scheme == "https",
            }

            response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
              http.request(request)
            end
        rescue => ex
            response = nil
        end
        if response.nil?
            nil
        else
            JSON(response.body.to_s)["access_token"].to_s rescue nil
        end
    end        

# Basic functions to access PIA ====================
    def defaultHeaders(token)
      { 'Accept' => '*/*',
        'Content-Type' => 'application/json',
        'Authorization' => 'Bearer ' + token }
    end

    def defaultHeadersPersonium(token)
      { 'Accept' => 'application/json',
        'Content-Type' => 'application/json',
        'Authorization' => 'Bearer ' + token }
    end

    def itemsUrl(url, repo_name)
      url + '/api/repos/' + repo_name + '/items'
    end

    def getToken(pia_url, app_key, app_secret)
        auth_url = pia_url.to_s + "/oauth/token"
        begin
            post_response = HTTParty.post(auth_url, 
                headers: { 'Content-Type' => 'application/json' },
                body: { client_id: app_key, 
                    client_secret: app_secret, 
                    grant_type: "client_credentials" }.to_json )
        rescue => ex
            post_response = nil
        end
        if post_response.nil?
            nil
        else
            post_response.parsed_response["access_token"].to_s
        end
    end

    def decrypt_message(message, keyStr)
        begin
            cipher = [JSON.parse(message)["value"]].pack('H*')
            nonce = [JSON.parse(message)["nonce"]].pack('H*')
            keyHash = RbNaCl::Hash.sha256(keyStr.force_encoding('ASCII-8BIT'))
            private_key = RbNaCl::PrivateKey.new(keyHash)
            authHash = RbNaCl::Hash.sha256('auth'.force_encoding('ASCII-8BIT'))
            auth_key = RbNaCl::PrivateKey.new(authHash).public_key
            box = RbNaCl::Box.new(auth_key, private_key)
            box.decrypt(nonce, cipher)
        rescue
            nil
        end
    end

    def setupApp(pia_url, app_key, app_secret)
      token = getToken(pia_url, app_key, app_secret)
      { "pia_url"    => pia_url,
        "app_key"    => app_key,
        "app_secret" => app_secret,
        "token"      => token }
    end

    def getWriteKey(app, repo)
        headers = defaultHeaders(app["token"])
        repo_url = app["pia_url"] + '/api/repos/' + repo + '/pub_key'
        get_response = HTTParty.get(repo_url, headers: headers).parsed_response
        if get_response.key?("public_key")
            get_response["public_key"]
        else
            nil
        end
    end

    def getReadKey(app)
        headers = defaultHeaders(app["token"])
        user_url = app["pia_url"] + '/api/users/current'
        get_response = HTTParty.get(user_url, headers: headers).parsed_response
        if get_response.key?("password_key")
            decrypt_message(get_response["password_key"], app["password"])
        else
            nil
        end
    end

    # CRUD operations ==========
    def readRawItems(app, repo_url)
        headers = defaultHeaders(app["token"])
        url_data = repo_url + '?size=2000'
        get_response = HTTParty.get(url_data, headers: headers)
        response_parsed = get_response.parsed_response
        if response_parsed.nil? or 
                response_parsed == "" or
                response_parsed.include?("error")
            nil
        else
            recs = get_response.headers["total-count"].to_i
            if recs > 2000
                (2..(recs/2000.0).ceil).each_with_index do |page|
                    url_data = repo_url + '?page=' + page.to_s + '&size=2000'
                    subresp = HTTParty.get(url_data,
                        headers: headers).parsed_response
                    response_parsed = response_parsed + subresp
                end
                response_parsed
            else
                response_parsed
            end
        end
    end

    def oydDecrypt(app, repo_url, data)
        private_key = getReadKey(app)
        if private_key.nil?
            nil
        else
            oyd_response = []
            data.each do |item|
                retVal = decrypt_message(item.to_s, private_key)
                retVal = JSON.parse(retVal.to_s) rescue {}
                retVal["id"] = JSON.parse(item)["id"]
                oyd_response << retVal
            end
            oyd_response
        end
    end

    def readItems(app, repo_url)
        if app.nil? || app == ""
            nil
        else
            respData = readRawItems(app, repo_url)
            if respData.nil?
                nil
            elsif respData.length == 0
                {}
            else
                data = JSON.parse(respData.first)
                if data.key?("version")
                    oydDecrypt(app, repo_url, respData)
                else
                    data
                end
            end
        end
    end

    def writeOydItem(app, repo_url, item)
        public_key_string = getWriteKey(app, "oyd.tally")
        public_key = [public_key_string].pack('H*')
        authHash = RbNaCl::Hash.sha256('auth'.force_encoding('ASCII-8BIT'))
        auth_key = RbNaCl::PrivateKey.new(authHash)
        box = RbNaCl::Box.new(public_key, auth_key)
        nonce = RbNaCl::Random.random_bytes(box.nonce_bytes)
        message = item.to_json
        msg = message.force_encoding('ASCII-8BIT')
        cipher = box.encrypt(nonce, msg)
        oyd_item = { "value" => cipher.unpack('H*')[0],
                     "nonce" => nonce.unpack('H*')[0],
                     "version" => "0.4" }
        writeItem(app, repo_url, oyd_item)
    end

    def writeItem(app, repo_url, item)
      headers = defaultHeaders(app["token"])
      data = item.to_json
      post_response = HTTParty.post(repo_url,
                               headers: headers,
                               body: data)
      post_response
    end

    def updateItem(app, repo_url, item, id)
      headers = defaultHeaders(app["token"])
      put_response = HTTParty.put(repo_url + "/" + id.to_s,
                               headers: headers,
                               body: item.to_json)
      put_response    
    end

    def deleteItem(app, repo_url, id)
      headers = defaultHeaders(app["token"])
      url = repo_url + '/' + id.to_s
      delete_response = HTTParty.delete(url,
                                 headers: headers)
      delete_response
    end

    def deleteRepo(app, repo_url)
      allItems = readItems(app, repo_url)
      if !allItems.nil?
        allItems.each do |item|
          deleteItem(app, repo_url, item["id"])
        end
      end
    end

end
