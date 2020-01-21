Rails.application.routes.draw do
  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html
	scope "(:locale)", :locale => /en|de/ do
		root  'pages#tally'
		get   'favicon',       to: 'pages#favicon'
		match '/tally',        to: 'pages#tally',        via: 'get'
		match '/tally',        to: 'pages#tally',        via: 'post'
		match 'increment',     to: 'pages#increment',    via: 'post'
		match '/write_data',   to: 'pages#write_data',   via: 'post'
		match '/new_topic',    to: 'pages#new_topic',    via: 'post'
		match '/remove_topic', to: 'pages#remove_topic', via: 'get'
		match '/error',        to: 'pages#error',        via: 'get'
		match '/app_config',   to: 'pages#app_config',   via: 'get'
		match '/password',     to: 'pages#password',     via: 'get'
	end
end
