#set :deploy_to, "/svc/google_daemon" # defaults to "/u/apps/#{application}"
#set :user, ""            # defaults to the currently logged in user
set :daemon_env, 'production'

set :domain, 'example.com'
server domain
