class PagesController < ApplicationController
	include ApplicationHelper

	def tally

		pds_type = params[:pds_type].to_s
		if pds_type.to_s == ""
			if params[:PIA_URL].to_s != ""
				pds_type = "oyd"
			else
				pds_type = session[:pds_type]
				if pds_type.to_s == ""
					pds_type = cookies.signed[:pds_type]
					if pds_type.to_s == ""
						redirect_to app_config_path
						return
					end
				end
			end
		end
		if pds_type.to_s != ""
			session[:pds_type] = pds_type
		end

		puts "PDS: " + pds_type.to_s

		case pds_type
		when "oyd"
			pia_url = params[:PIA_URL].to_s
			if pia_url.to_s == ""
				pia_url = session[:pia_url]
				if pia_url.to_s == ""
					pia_url = cookies.signed[:pia_url]
				end
			end
			if pia_url.to_s != ""
				session[:pia_url] = pia_url
			end
			host_url = pia_url

			app_key = params[:APP_KEY].to_s
			if app_key.to_s == ""
				app_key = session[:app_key]
				if app_key.to_s == ""
					app_key = cookies.signed[:app_key]
				end
			end
			if app_key.to_s != ""
				session[:app_key] = app_key
			end

			app_secret = params[:APP_SECRET].to_s
			if app_secret.to_s == ""
				app_secret = session[:app_secret]
				if app_secret.to_s == ""
					app_secret = cookies.signed[:app_secret]
				end
			end
			if app_secret.to_s != ""
				session[:app_secret] = app_secret
			end

			app = setupApp(pia_url, app_key, app_secret)
			session[:oyd_app] = app

			token = app["token"]
			if token == ""
				redirect_to app_config_path(pia_url: pia_url)
				return
			end

			nonce = params[:NONCE].to_s
			if nonce.to_s == ""
				nonce = session[:nonce].to_s
				if nonce.to_s == ""
					nonce = cookies.signed[:nonce].to_s
				end
			end
			if nonce.to_s != ""
				session[:nonce] = nonce
			end

			master_key = params[:MASTER_KEY].to_s
			if master_key.to_s == ""
				master_key = session[:master_key].to_s
				if master_key.to_s == ""
					master_key = cookies.signed[:master_key].to_s
					if master_key == ""
						nonce = ""
					end
				end
			end
			if master_key.to_s != ""
				session[:master_key] = master_key
			end

			password = params[:password].to_s
			if password.to_s == "" && nonce.to_s == ""
				password = session[:password].to_s
				if password.to_s == "" && nonce.to_s == ""
					password = cookies.signed[:password]
					if password.to_s != ""
						cookie_password = true
					end
				end
			else
				session[:password] = password
				if params[:remember].to_s == "1"
					cookies.permanent.signed[:pds_type] = pds_type
					cookies.permanent.signed[:pia_url] = pia_url
					cookies.permanent.signed[:app_key] = app_key
					cookies.permanent.signed[:app_secret] = app_secret
					cookies.permanent.signed[:password] = password
				end
			end
			if password.to_s == "" && nonce != ""
				begin
					# get cipher
			        nonce_url = pia_url + '/api/support/' + nonce
			        response = HTTParty.get(nonce_url)
			        if response.code == 200
			        	cipher = response.parsed_response["cipher"]
			        	cipherHex = [cipher].pack('H*')
			            nonceHex = [nonce].pack('H*')
		            	keyHash = [master_key].pack('H*')
		            	private_key = RbNaCl::PrivateKey.new(keyHash)
		            	authHash = RbNaCl::Hash.sha256('auth'.force_encoding('ASCII-8BIT'))
		            	auth_key = RbNaCl::PrivateKey.new(authHash).public_key
		            	box = RbNaCl::Box.new(auth_key, private_key)
		            	password = box.decrypt(nonceHex, cipherHex)

			        	# write to cookies in any case if NONCE is provided in URL
						cookies.permanent.signed[:pia_url] = pia_url
						cookies.permanent.signed[:app_key] = app_key
						cookies.permanent.signed[:app_secret] = app_secret
						cookies.permanent.signed[:password] = password
						cookies.permanent.signed[:pds_type] = pds_type
			        end
			    rescue
			    	password = ""
			    end
		    end

			if password.to_s == ""
				password = session[:password].to_s
				if password.to_s == ""
					password = cookies.signed[:password]
				end
			end

			cookie_password = false
			if password.to_s == ""
				redirect_to password_path(pia_url: pia_url, app_key: app_key, app_secret: app_secret)
				return
			else
				app["password"] = password.to_s
				session[:password] = password
			end

			@pia_url = pia_url
			@app_key = app_key
			@app_secret = app_secret

		when "ceps"
			ceps_url = params[:CEPS_URL].to_s
			if ceps_url.to_s == ""
				ceps_url = session[:ceps_url]
				if ceps_url.to_s == ""
					ceps_url = cookies.signed[:ceps_url]
				end
			end
			if ceps_url.to_s != "" 
				session[:ceps_url] = ceps_url
			end
			host_url = ceps_url

			ceps_user = params[:CEPS_USER].to_s
			if ceps_user.to_s == ""
				ceps_user = session[:ceps_user]
				if ceps_user.to_s == ""
					ceps_user = cookies.signed[:ceps_user]
				end
			end
			if ceps_user.to_s != ""
				session[:ceps_user] = ceps_user
			end

			ceps_password = params[:CEPS_PASSWORD].to_s
			if ceps_password.to_s == ""
				ceps_password = session[:ceps_password]
				if ceps_password.to_s == ""
					ceps_password = cookies.signed[:ceps_password]
				end
			end
			if ceps_password.to_s != ""
				session[:ceps_password] = ceps_password
			end

			token = session[:ceps_token].to_s
			if token == ""
				token = cookies.signed[:ceps_token].to_s
				if token == ""
					token = getCepsToken(ceps_url, ceps_user, ceps_password)
					if token.nil? || token == ""
						redirect_to app_config_path
						return
					end
					session[:ceps_token] = token
					if params[:remember].to_s == "1"
						cookies.permanent.signed[:ceps_token] = token
					end
				end
			end

		when "personium"
			personium_url = params[:PERSONIUM_URL].to_s
			if personium_url.to_s == ""
				personium_url = session[:personium_url]
				if personium_url.to_s == ""
					personium_url = cookies.signed[:personium_url]
				end
			end
			if personium_url.to_s != "" 
				session[:personium_url] = personium_url
			end
			host_url = personium_url

			personium_user = params[:PERSONIUM_USER].to_s
			if personium_user.to_s == ""
				personium_user = session[:personium_user]
				if personium_user.to_s == ""
					personium_user = cookies.signed[:personium_user]
				end
			end
			if personium_user.to_s != ""
				session[:personium_user] = personium_user
			end

			personium_password = params[:PERSONIUM_PASSWORD].to_s
			if personium_password.to_s == ""
				personium_password = session[:personium_password]
				if personium_password.to_s == ""
					personium_password = cookies.signed[:personium_password]
				end
			end
			if personium_password.to_s != ""
				session[:personium_password] = personium_password
			end

			token = getPersoniumToken(personium_url, personium_user, personium_password)
			if token.to_s == ""
				redirect_to app_config_path
				return
			end	
			session[:personium_token] = token
			if params[:remember].to_s == "1"
				cookies.permanent.signed[:personium_token] = token
			end

		else
			redirect_to app_config_path
			return
		end

		session[:token] = token
		if request.post?
			redirect_to root_path
		end

		case pds_type
		when "oyd"
			tally_url = itemsUrl(app["pia_url"], "oyd.tally")
			tally_data = readItems(app, tally_url)
		when "ceps"
			tally_url = host_url + "/ceps/query/eu.oyd.tallyzoo"
			headers = defaultHeaders(token)
			response = HTTParty.post(tally_url,
                           			 headers: headers,
                           			 body: {"collection_name": "overview"}.to_json)
			tally_data = JSON(response.parsed_response.to_s)["results"] rescue []
		when "personium"
			tally_url = host_url + "/app-tally-zoo/attributes/overview.json"
			headers = defaultHeadersPersonium(token)
			response = HTTParty.get(tally_url,
									headers: headers)
			tally_data = nil
			if response.code == 200
				tally_data = response.parsed_response
			end
		end
		@topics = []
		tally_data.each do |item|
			if item.key?("name") && item.key?("identifier") && item.key?("value") && item.key?("timestamp")
				if !item.key?("hide")
					@topics << item.stringify_keys
				end
			end
		end unless tally_data.nil?
		if @topics.count == 0
			@topics = [{"name": "default",
						"identifier": "oyd.tally.default",
						"value": "0",
						"timestamp": Time.now.utc.to_i}.stringify_keys]
		end
	end

	def error
		@pia_url = params[:pia_url]
	end

	def app_config
		@pia_url = params[:pia_url]
		@app_key = params[:app_key]
		@app_secret = params[:app_secret]
	end

	def write_tally(repo, tally_name, value)
		case session[:pds_type].to_s
		when "oyd"
			if session[:oyd_app].nil?
				app = setupApp(session[:pia_url], session[:app_key], session[:app_secret])
				session[:oyd_app] = app
			else
				app = session[:oyd_app]
			end
			app["password"] = session[:password]
			tally_url = itemsUrl(app["pia_url"], repo)
			tally_data = { "timestamp" => DateTime.now.strftime('%s').to_i, "value": value.to_s }
			retVal = writeOydItem(app, tally_url, tally_data)
			tally_data = readItems(app, tally_url)
			topic_value = nil
			tally_data.each do |item|
				cur_value = item["value"].to_i rescue 0
				if topic_value.nil?
					topic_value = cur_value
				else
					topic_value += cur_value
				end
			end unless tally_data.nil?
			if topic_value.nil?
				topic_value = value
			end

			tally_url = itemsUrl(app["pia_url"], "oyd.tally")
			tally_data = readItems(app, tally_url)
			topic_name = "default"
			topic_identifier = "oyd.tally.default"
			topic_color = "cyan"
			topic_id = nil
			tally_data.each do |item|
				if item["identifier"].to_s == repo
					topic_id = item["id"]
					topic_name = item["name"]
					topic_color = item["color"]
					topic_identifier = item["identifier"]
				end
			end unless tally_data.nil?
			record = { "name": topic_name,
					   "identifier": topic_identifier,
					   "value": topic_value.to_s,
					   "color": topic_color.to_s,
					   "timestamp": Time.now.utc.to_i }

	        public_key_string = getWriteKey(app, "oyd.tally")
	        public_key = [public_key_string].pack('H*')
	        authHash = RbNaCl::Hash.sha256('auth'.force_encoding('ASCII-8BIT'))
	        auth_key = RbNaCl::PrivateKey.new(authHash)
	        box = RbNaCl::Box.new(public_key, auth_key)
	        nonce = RbNaCl::Random.random_bytes(box.nonce_bytes)
	        message = record.to_json
	        msg = message.force_encoding('ASCII-8BIT')
	        cipher = box.encrypt(nonce, msg)
	        oyd_item = { "value" => cipher.unpack('H*')[0],
	                     "nonce" => nonce.unpack('H*')[0],
	                     "version" => "0.4" }

	        if tally_data.nil?
	        	retVal = writeItem(app, tally_url, oyd_item)
	        else
				if topic_id.nil?
					return
				end
				retVal = updateItem(app, tally_url, oyd_item, topic_id)
			end

		when "ceps"
			token = session[:ceps_token]
			headers = defaultHeaders(token)
			tally_url = session[:ceps_url] + "/ceps/write/eu.oyd.tallyzoo/" + tally_name.to_s
			tally_data = { "data": { "timestamp" => DateTime.now.strftime('%s').to_i, "value": value.to_s } }
			response = HTTParty.post(tally_url,
                           			 headers: headers,
                           			 body: tally_data.to_json)

			tally_url = session[:ceps_url] + "/ceps/query/eu.oyd.tallyzoo"
			headers = defaultHeaders(token)
			response = HTTParty.post(tally_url,
                           			 headers: headers,
                           			 body: {"collection_name": "overview"}.to_json).parsed_response
			tally_data = JSON(response.to_s)["results"] rescue []
			updated = false
			tally_data.each do |item|
				item_identifier = item["identifier"].to_s rescue ""
				if item_identifier == repo.to_s && !item.key?("hide")
					tally_url = session[:ceps_url] + "/ceps/write/eu.oyd.tallyzoo/overview"
					tally_data = { "data": { "name": tally_name.to_s,
										     "identifier": repo.to_s,
										     "value": (item["value"].to_i+value).to_s,
										     "color": item["color"].to_s,
										     "timestamp": Time.now.utc.to_i },
								   "options": { "update": true,
								   				"data_object_id": item["_id"].to_s } }
					response = HTTParty.post(tally_url,
		                           			 headers: headers,
		                           			 body: tally_data.to_json)
					updated = true
				end
			end unless tally_data.nil?
			if !updated
				tally_url = session[:ceps_url] + "/ceps/write/eu.oyd.tallyzoo/overview"
				tally_data = { "data": { "name": tally_name.to_s,
									     "identifier": repo.to_s,
									     "value": value.to_s,
									     "timestamp": Time.now.utc.to_i } }
				response = HTTParty.post(tally_url,
	                           			 headers: headers,
	                           			 body: tally_data.to_json).parsed_response

			end

		when "personium"
			token = session[:personium_token]
			headers = defaultHeadersPersonium(token)
			topic_value = nil

			# create detail entry
			tally_url = session[:personium_url] + "/app-tally-zoo/attributes/" + tally_name.to_s + ".json"
			tally_data = { "timestamp" => DateTime.now.strftime('%s').to_i, "value": value.to_s }
			response = HTTParty.get(tally_url, headers: headers)
			if response.code == 200
				data = response.parsed_response
				data << tally_data
				response = HTTParty.put(tally_url, headers: headers, body: data.to_json)
				# iterate over each entry to get current sum
				data.each do |item|
					cur_value = item["value"].to_i rescue 0
					if topic_value.nil?
						topic_value = cur_value
					else
						topic_value += cur_value
					end
				end unless data.nil?
				if topic_value.nil?
					topic_value = value
				else
					topic_value += value
				end
			else
				response = HTTParty.put(tally_url, headers: headers, body: [tally_data].to_json)
				topic_value = value
			end

			# update overview
			tally_url = session[:personium_url] + "/app-tally-zoo/attributes/overview.json"
			response = HTTParty.get(tally_url, headers: headers)
			if response.code == 200
				new_data = []
				data = response.parsed_response
				data.each do |item|
					if item["identifier"].to_s == repo
						new_data << { "name": item["name"].to_s,
									  "identifier": repo.to_s,
									  "value": topic_value.to_s,
									  "color": item["color"].to_s,
									  "timestamp": Time.now.utc.to_i }
					else
						new_data << item
					end
				end unless tally_data.nil?
				if new_data.count == 0
					new_data = [{ "name": "default",
								  "identifier": "oyd.tally.default",
								  "value": topic_value.to_s,
								  "color": "cyan",
								  "timestamp": Time.now.utc.to_i }]
				end
			else
				new_data = [{ "name": "default",
							  "identifier": "oyd.tally.default",
							  "value": topic_value.to_s,
							  "color": "cyan",
							  "timestamp": Time.now.utc.to_i }]
			end
			response = HTTParty.put(tally_url, headers: headers, body: new_data.to_json)

		else
			puts "unknown PDS_TYPE"
		end

	end

	def delete_tally(repo, tally_name)
		case session[:pds_type]
		when "oyd"
			app = setupApp(session[:pia_url], session[:app_key], session[:app_secret])
			app["password"] = session[:password]
			tally_url = itemsUrl(app["pia_url"], "oyd.tally")
			tally_data = readItems(app, tally_url)
			tally_data.each do |item|
				if item["identifier"].to_s == repo
					retVal = deleteItem(app, tally_url, item["id"])
				end
			end unless tally_data.nil?
			repo_url = app["pia_url"].to_s + '/api/repos/' + repo.to_s + '/identifier'
			headers = defaultHeaders(app["token"])
	        response = HTTParty.get(repo_url, headers: headers).parsed_response.stringify_keys
	        repo_id = response["id"].to_s
	        repo_url = app["pia_url"].to_s + '/api/repos/' + repo_id
	        response = HTTParty.delete(repo_url, headers: headers)

	    when "ceps"
			token = session[:ceps_token]
			headers = defaultHeaders(token)
			tally_url = session[:ceps_url] + "/ceps/query/eu.oyd.tallyzoo"
			response = HTTParty.post(tally_url,
                           			 headers: headers,
                           			 body: {"collection_name": "overview"}.to_json).parsed_response
			tally_data = JSON(response.to_s)["results"] rescue []
			tally_data.each do |item|
				item_identifier = item["identifier"].to_s rescue ""
				if item_identifier == repo.to_s
					tally_url = session[:ceps_url] + "/ceps/write/eu.oyd.tallyzoo/overview"
					tally_data = { "data": { "name": tally_name.to_s,
										     "identifier": repo.to_s,
										     "value": item["value"].to_s,
										     "color": item["color"].to_s,
										     "timestamp": Time.now.utc.to_i,
										     "hide": true },
								   "options": { "update": true,
								   				"data_object_id": item["_id"].to_s } }
					response = HTTParty.post(tally_url,
		                           			 headers: headers,
		                           			 body: tally_data.to_json)
				end
			end

		when "personium"
			token = session[:personium_token]
			headers = defaultHeadersPersonium(token)
			tally_url = session[:personium_url] + "/app-tally-zoo/attributes/overview.json"
			response = HTTParty.get(tally_url, headers: headers)
			if response.code == 200
				new_data = []
				data = response.parsed_response
				data.each do |item|
					if item["identifier"].to_s != repo
						new_data << item
					end
				end unless data.nil?
				response = HTTParty.put(tally_url, headers: headers, body: new_data.to_json)
				tally_detail_url = session[:personium_url] + "/app-tally-zoo/attributes/" + tally_name.to_s + ".json"
				response = HTTParty.delete(tally_detail_url, headers: headers)
			end

	    end

	end

	def new_topic
		case session[:pds_type].to_s
		when "oyd"
			app = setupApp(session[:pia_url], session[:app_key], session[:app_secret])
			tally_url = itemsUrl(app["pia_url"], "oyd.tally")
			new_item = { "name": params[:topic_name].to_s,
				         "color": params[:topic_color].to_s,
					     "identifier": "oyd.tally." + str2ascii(params[:topic_name].to_s),
					     "value": "0",
					     "timestamp": Time.now.utc.to_i }
			retVal = writeOydItem(app, tally_url, new_item)

		when "ceps"
			token = session[:ceps_token]
			headers = defaultHeaders(token)
			tally_url = session[:ceps_url] + "/ceps/write/eu.oyd.tallyzoo/overview"
			tally_data = { "data": { "name": params[:topic_name].to_s,
									 "color": params[:topic_color].to_s,
								     "identifier": "oyd.tally." + str2ascii(params[:topic_name]).to_s,
								     "value": "0",
								     "timestamp": Time.now.utc.to_i } }
			response = HTTParty.post(tally_url,
                           			 headers: headers,
                           			 body: tally_data.to_json).parsed_response

		when "personium"
			token = session[:personium_token]
			headers = defaultHeadersPersonium(token)
			tally_url = session[:personium_url] + "/app-tally-zoo/attributes/overview.json"

			new_item = { "name": params[:topic_name].to_s,
				         "color": params[:topic_color].to_s,
					     "identifier": "oyd.tally." + str2ascii(params[:topic_name].to_s),
					     "value": "0",
					     "timestamp": Time.now.utc.to_i }

			response = HTTParty.get(tally_url,
									 headers: headers)
			if response.code == 200
				data = response.parsed_response
				data << new_item
				response = HTTParty.put(tally_url, headers: headers,
					body: data.to_json)

			else
				response = HTTParty.put(tally_url, headers: headers,
					body: [new_item].to_json)
			end

		else
			puts "unknown PDS Type"
		end
		redirect_to root_path
		
	end

	def increment
		tally_repo = params[:tally_repo].to_s
		tally_name = params[:tally_name].to_s
		tally_increment = params[:tally_increment].to_i rescue 1
		write_tally(tally_repo, tally_name, tally_increment)
		head 200, content_type: "text/html"
	end

	def remove_topic
		tally_repo = params[:tally_repo].to_s
		tally_name = params[:tally_name].to_s
		delete_tally(tally_repo, tally_name)
		redirect_to root_path
	end

	def password
		@pia_url = params[:pia_url]
		@app_key = params[:app_key]
		@app_secret = params[:app_secret]
	end
		
	def favicon
		send_file 'public/favicon.ico', type: 'image/x-icon', disposition: 'inline'
	end

end