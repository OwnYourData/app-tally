Rails.application.routes.draw do
  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html
	scope "(:locale)", :locale => /en|de/ do
		root  'pages#topics'
		get   'favicon',     to: 'pages#favicon'
		match '/topics',     to: 'pages#topics',     via: 'get'
		match '/topics',     to: 'pages#topics',     via: 'post'
		match '/write_data', to: 'pages#write_data', via: 'post'
		match '/error',      to: 'pages#error',      via: 'get'
		match '/app_config', to: 'pages#app_config', via: 'get'
		match '/password',   to: 'pages#password',   via: 'get'
	end
end
