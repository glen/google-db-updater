CONFIG = DaemonKit::Config.load('config.yml')

require 'rufus/tokyo'
require 'ruby-debug'

# Create the connection to the database
# Check the key 'version' if not present then add the key 'version' with value "-1.1"
# Finally close the connection to the database
$db = Rufus::Tokyo::Cabinet.new("#{DAEMON_ROOT}/db/#{CONFIG['db_database']}")
$db['version'] = "-1.1" unless $db['version']
$db.close
