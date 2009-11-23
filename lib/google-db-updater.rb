# Your starting point for daemon specific classes. This directory is
# already included in your load path, so no need to specify it.

# Require all files in lib directory

class GoogleSafeBrowsing
  @@user_api_key = CONFIG[:google_api_key]
  @@response = nil
  @@failure = 0
  @@interval = 28.minutes
  @@process = nil
  
  def initialize
    loop do
      if @@process.nil? || !alive?(@@process)
        DaemonKit.logger.info "No update process on. Updating..."
        @@process = nil
        update_malware_hash
        Process.detach(@@process) if @@process # Checking if this works as well. Should create another process to reap the status of the child process (To prevent Zombie Processes)
      else
        DaemonKit.logger.info "Sleeping for #{5.minutes.to_i/60} minutes as previous process still on."
        Process.wait(@@process, 1) # Not too sure if this is needed. (To prevent Zombie Processes)
        @@interval = 5.minutes
      end
      # Sleeping until next update
      DaemonKit.logger.info "Sleeping for #{@@interval.to_i/60} minutes"
      sleep(@@interval.to_i)
      DaemonKit.logger.info "Waking Up!"
    end
  end

  ##
  # Opens the db connection
  #
  def self.open_db
    $db = Rufus::Tokyo::Cabinet.new("#{DAEMON_ROOT}/db/#{CONFIG['db_database']}")
  end

  ##
  # Close the db connection
  #
  def self.close_db
    $db.close
  end

  ##
  # Retrieves the version of the Google Safe Browsing Database
  #
  def self.version
    GoogleSafeBrowsing.open_db
    version = $db['version']
    GoogleSafeBrowsing.close_db
    version
  end

  ##
  # Retrieves the size of the database
  #
  def self.db_size
    GoogleSafeBrowsing.open_db
    size = $db.size == 0 ? 0 : $db.size - 1
    GoogleSafeBrowsing.close_db
    size
  end
  
  ##
  # In case malware_hashes_file present, request an update from the version present.
  #
  def update_malware_hash
    DaemonKit.logger.info "Malware version: #{GoogleSafeBrowsing.version}, having #{GoogleSafeBrowsing.db_size} url's. Updating malware hashes..."
    begin
      # ****malware hash****
      @@response = Net::HTTP.get(URI.parse("http://sb.google.com/safebrowsing/update?client=api&apikey=#{@@user_api_key}&version=goog-malware-hash:#{GoogleSafeBrowsing.version.slice(/\d+/)}:#{GoogleSafeBrowsing.version.slice(/\d+\Z/)}"))
      # ****black list hash****
      # @@response = Net::HTTP.get(URI.parse("http://sb.google.com/safebrowsing/update?client=api&apikey=#{@@user_api_key}&version=goog-black-hash:#{GoogleSafeBrowsing.version.slice(/\d+/)}:#{GoogleSafeBrowsing.version.slice(/\d+\Z/)}"))
      @@failure = 0
      # For an Update Normal interval is between 25 and 30 minutes
      # For a fresh file 1 hour is required for writing to the SQLite database
      @@interval = 28.minutes
    rescue Timeout::Error
      DaemonKit.logger.info "Timeour Error!"
      @@failure += 1
      @@interval = case @@failure
        when 1..2:    1.minute  # less than 3 consecutive errors update in 1 minute
        when    3:   60.minutes # on 3rd consecutive error update in 60 minutes
        when    4:  180.minutes # on 4th consecutive error update in 180 minutes
        else        360.minutes # more than 4 consecutive errors update in 360.minutes
      end
      return
    rescue SocketError
      DaemonKit.logger.info "Socket Error!"
      @@interval = 15.minutes
      return
    end

    unless @@response.empty?
      @@process = Process.fork do
        DaemonKit.logger.info "Started fork for adding to database..."
        GoogleSafeBrowsing.save_updated_malware_hash
        DaemonKit.logger.info "Ended fork for adding to database!"
        Process.exit!(0) # exit  (To prevent Zombie Processes)
      end
    else
      DaemonKit.logger.info "Nothing to update"
    end
  end

  ##
  # Save the updated malware hashes to @@malware_hashes
  #
  def GoogleSafeBrowsing.save_updated_malware_hash
    malware_hashes_version = ""
    added_ary = []
    removed_list = []
    removed_ary = []
    not_found_ary = []
    @@response.split("\n").each{|x| x.strip!}.each do |y|
      ##
      # 2 possibilites 
      # 1 => an update is received [goog-malware-hash 1.2313 update]
      # 2 => a completed new list is received [goog-malware-hash 1.2313]
#      if y.match(/\[goog-black-hash \d+\.\d+ update\]/) # for an update ****black list hash****
      if y.match(/\[goog-malware-hash \d+\.\d+ update\]/) # for an update ****malware hash****
        # Update the malware_hashes_version to the latest one.
        malware_hashes_version = y.slice(/\d+\.\d+/)
        DaemonKit.logger.info "Received an update - #{malware_hashes_version}"
#      elsif y.match(/\[goog-black-hash \d+\.\d+\]/) # for a new list  ****black list hash****
      elsif y.match(/\[goog-malware-hash \d+\.\d+\]/) # for a new list  ****malware hash****
        # Delete the hashed_urls in the list table
        DaemonKit.logger.info "Deleting table contents"
        # 'clear' will deleted everything including the version TODO clear is not working
        # So we keep a copy of the old version in a variable, clear the database and then add the version again.
        old_version = GoogleSafeBrowsing.version

        GoogleSafeBrowsing.open_db
        keys = $db.keys
        $db.ldelete(keys)
        GoogleSafeBrowsing.close_db

        update_version_to(old_version)
        DaemonKit.logger.info "Deleted all table contents"
        
        # Update the malware_hashes_version to the latest one.
        malware_hashes_version = y.slice(/\d+\.\d+/)
        DaemonKit.logger.info "Received a fresh list - #{malware_hashes_version}"
        # resetting @@malware_hashes
      else
        # '+' at begining equals an addition to the list of malware infected sites
        if y[0] && (y[0].chr == '+')
          added_ary << y.slice(1,32)
          
        # '-' at begining equals a removal of a malware infected site
        elsif y[0] && (y[0].chr == '-')
          removed_list << y.slice(1,32)
        end      
      end
    end

    if !(malware_hashes_version.empty?) && malware_hashes_version != GoogleSafeBrowsing.version
      # This is in case any break when adding to the database
      # We update the version to 1.-1 and then dump to database.
      # After completion we add
      update_version_to("-1.1")
      DaemonKit.logger.info "Adding urls to the database!!"
      add_urls = {}
      added_ary.each{|url| add_urls.merge!({url => ""})}

      GoogleSafeBrowsing.open_db
      $db.lput(add_urls) unless add_urls.empty?
      GoogleSafeBrowsing.close_db

      DaemonKit.logger.info "Added urls to the database!!"
      
      # Take the list of urls to delete and query db
      # Returns only a list of url's that are present - these need to be removed from the database
      # The rest are not found in the db
      GoogleSafeBrowsing.open_db
      removed_ary = $db.lget(removed_list).keys
      GoogleSafeBrowsing.close_db      
      not_found_ary = removed_list - removed_ary

      DaemonKit.logger.info "Removing urls from database....."
      GoogleSafeBrowsing.open_db
      $db.ldelete(removed_ary) unless removed_ary.empty?
      GoogleSafeBrowsing.close_db
      DaemonKit.logger.info "Removed urls from database!!"
      update_version_to(malware_hashes_version)
   
      DaemonKit.logger.info "Saved updated Malware hashes! Updated to - #{GoogleSafeBrowsing.version}"
      DaemonKit.logger.info "Total #{GoogleSafeBrowsing.db_size} | Added #{added_ary.length} | Removed #{removed_ary.length} | Not found #{not_found_ary.length}"
    end
    # Resetting @@response to get new response
    @@response = nil
  end
   
  ##
  # Update the malware version no
  # We set default to "" this is an indication that database updation is happening and hence table data is incomplete
  # The query program would check if there is a version available before getting the list of hashed_urls
  def self.update_version_to(version = "")
    GoogleSafeBrowsing.open_db
    $db['version'] =  version
    GoogleSafeBrowsing.close_db
  end
   
  ##
  # Used to prevent a new process from starting if the previous process of updation of malware is incomplete
  #
  def alive? pid
    pid = Integer("#{ pid }")
    begin
      Process::kill 0, pid
      true
    rescue Errno::ESRCH
      false
    end
  end
end
GoogleSafeBrowsing.new
