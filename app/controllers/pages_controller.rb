class PagesController < ApplicationController
	include ApplicationHelper

	def topics
		pds_type = params[:pds_type].to_s
		if pds_type.to_s == ""
			pds_type = session[:pds_type]
			if pds_type.to_s == ""
				pds_type = cookies.signed[:pds_type]
			end
		else
			session[:pds_type] = pds_type
		end

		pia_url = params[:PIA_URL].to_s
		if pia_url.to_s == ""
			pia_url = session[:pia_url]
			if pia_url.to_s == ""
				pia_url = cookies.signed[:pia_url]
			end
		else
			session[:pia_url] = pia_url
		end

		app_key = params[:APP_KEY].to_s
		if app_key.to_s == ""
			app_key = session[:app_key]
			if app_key.to_s == ""
				app_key = cookies.signed[:app_key]
			end
		else
			session[:app_key] = app_key
		end

		app_secret = params[:APP_SECRET].to_s
		if app_secret.to_s == ""
			app_secret = session[:app_secret]
			if app_secret.to_s == ""
				app_secret = cookies.signed[:app_secret]
			end
		else
			session[:app_secret] = app_secret
		end

		desktop = params[:desktop].to_s
		if desktop == ""
			desktop = session[:desktop]
			if desktop == ""
				desktop = false
			else
				if desktop == "1"
					desktop = true
				else
					desktop = false
				end
			end
		else
			if desktop == "1"
				desktop = true
			else
				desktop = false
			end
		end
		puts "Desktop:" + desktop.to_s
		if desktop
			session[:desktop] = "1"
		else
			session[:desktop] = "0"
		end

		nonce = params[:NONCE].to_s
		if nonce.to_s == ""
			nonce = session[:nonce].to_s
			if nonce.to_s == ""
				nonce = cookies.signed[:nonce].to_s
			end
		else
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
		else
			session[:master_key] = master_key
		end

		password = ""
		if nonce == ""
			password = params[:password].to_s
		else
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

		        end
		    rescue
		    	password = ""
		    end
	    end
		cookie_password = false
		if password.to_s == ""
			password = session[:password].to_s
			if password.to_s == ""
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
		@pia_url = pia_url
		@app_key = app_key
		@app_secret = app_secret

		# puts "pia_url: " + pia_url.to_s
		# puts "app_key: " + app_key.to_s
		# puts "app_secret: " + app_secret.to_s
		# puts "password: " + password.to_s

		token = getToken(pia_url, app_key, app_secret).to_s
		if token == ""
			redirect_to app_config_path(pia_url: pia_url)
			# redirect_to error_path(pia_url: pia_url)
			return
		end
		session[:token] = token

		if password.to_s == ""
			redirect_to password_path(pia_url: pia_url)
			return
		end
		app = setupApp(pia_url, app_key, app_secret)
		app["password"] = password.to_s
		if getReadKey(app).nil?
			if cookie_password
				flash[:warning] = t('general.wrongCookiePassword')
			else
				flash[:warning] = t('general.wrongPassword')
			end
			redirect_to password_path(pia_url: pia_url, app_key: app_key, app_secret: app_secret)
			return
		end
		if request.post?
			redirect_to root_path
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

	def write_data
		case session[:pds_type]
		when "oyd"
			puts "we are here"
			app = setupApp(session[:pia_url], session[:app_key], session[:app_secret])
			app["password"] = session[:password]
			tally_url = itemsUrl(app["pia_url"], "oyd.tally")
			tally_data = { "timestamp" => DateTime.now.strftime('%s').to_i }
			retVal = writeOydItem(app, tally_url, tally_data)
		else
			puts "unknown PDS_TYPE"
		end
		redirect_to root_path
	end

	def favicon
		send_file 'public/favicon.ico', type: 'image/x-icon', disposition: 'inline'
	end

end