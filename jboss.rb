# copyright: 2018, The Authors

# if in domain mode this file exists: $JVM_HOME/configuration/domain.xml

# jvm_home /tech/appl/chef9/jb_apps/poc-chefjb/poc-chefjb_s01
#   user -> chef9
#   app-suite -> poc-chefjb
#   jvm -> poc-chefjb_s01

title 'HIG - IBM Red Hat JBoss Application Server Controls'

JBOSS_HOME = "/tech/appl/Redhat/jboss-eap-7.1.4"

control 'jboss-01' do
  impact 1.0
  title 'JBoss Application Server Process ID'
  desc 'Local OS user ID under which JBoss Ap-plication Server processes run.'
  tag requirements: 'S - healthcheck and baseline'
  tag section: 'BW.1.1.2.1'
  tag heading: 'Passwords'
  tag action: 'ID must not have system administration (root) authority.'
  tag remediate: 'no'

  processes(/\/tech\/appl\/java\/.*\/bin\/java/).where { pid > 0 }.entries.each do |entry|
    describe user(entry.user) do
      its('groups') { should_not eq 'root' }
    end
  end
end

control 'jboss-02' do
  impact 1.0
  title 'JVM Logging must exist'
  desc 'JVM Logging must exist'
  tag requirements: 'S - healthcheck and baseline'
  tag section: 'BW.1.2.2'
  tag heading: 'Logging'
  tag action: 'JVM Logging must exist'

  processes(/\/tech\/appl\/java\/.*\/bin\/java/).where { pid > 0 }.entries.each do |entry|
    server_log = entry.command.split(' ').select{ |word| word.include? "-Djboss.server.log.dir=" }[0].split('=')[1] + '/server.log'
    describe file(server_log) do
      it { should exist }
    end
  end
end

control 'jboss-03' do
  impact 1.0
  title 'Password Storage'
  desc 'JBoss KeyStore and Truststore passwords must not be stored in clear text'
  tag requirements: 'B - baseline'
  tag section: 'BW.6.1.1.10'
  tag heading: 'Password Controls'
  tag action: 'JBoss KeyStore and Truststore passwords will be stored in the password vault'

  processes(/\/tech\/appl\/java\/.*\/bin\/java/).where { pid > 0 }.entries.each do |entry|
    config_xml = entry.command.split(' ').select{ |word| word.include? "-Djboss.server.base.dir=" }[0].split('=')[1] + '/configuration/standalone-full-ha.xml'
    describe file(config_xml) do
      it { should exist }
    end
    describe xml(config_xml) do
      its ('server/management/security-realms/security-realm/server-identities/ssl/keystore/attribute::keystore-password') { should include "${VAULT::SSL::MGMTSSL::1}" }
    end
  end
end

control 'jboss-04' do
  impact 1.0
  title 'Management interfaces'
  desc 'Assign the management interfaces to the management realm'
  tag requirements: 'S - healthcheck and baseline'
  tag section: 'BW.6.1.4.1'
  tag heading: 'System Settings'

  # By default, JBoss provides two management interfaces; they are named "NATIVE-INTERFACE" and "HTTP-INTERFACE".
  # The system may or may not have both interfaces enabled. For each management interface listed as a result of
  # the previous command, append the name of the management interface
  #
  tag action: ''

  # export JAVA_HOME=/tech/appl/java/jdk1.8.0_71 ; export JAVA=/tech/appl/java/jdk1.8.0_71/bin/java ; export PATH=$PATH:$JAVA_HOME/bin"
  # HOST_NAME => hostname
  # MGMT_HTTPS_PORT => 22005
  # $JBOSS_HOME/bin/jboss-cli.sh --connect --controller=https-remoting://$HOST_NAME:$MGMT_HTTPS_PORT --command="/core-service=management/management-interface=http-interface:read-attribute(name=security-realm)"

  processes(/\/tech\/appl\/java\/.*\/bin\/java/).where { pid > 0 }.entries.each do |entry|
    java_home_str = Pathname.new(entry.command.split(' ')[0]).dirname + ".."
    java_home = java_home_str.cleanpath
    appl_host = inspec.command('hostname').stdout.chomp
    appl_port = entry.command.split(' ').select{ |word| word.include? "-Djboss.socket.binding.port-offset=" }[0].split('=')[1].to_i + 20000 + 5
    describe bash("(export JAVA_HOME=#{java_home} && export JAVA=#{java_home}/bin/java && export PATH=$PATH:#{java_home}/bin && #{JBOSS_HOME}/bin/jboss-cli.sh --connect --controller=https-remoting://#{appl_host}:#{appl_port} --command='/core-service=management/management-interface=http-interface:read-attribute(name=security-realm)')") do
      its('exit_status') { should eq 0 }
      #its('stderr') { should match 'none' }
      its('stdout') { should match /\"result\" => \"CustomRealm\"/ }
    end
  end
end

control 'jboss-05' do
  impact 1.0
  title 'LDAP enabled security realm value allow-empty-passwords must be set to false.'
  desc 'LDAP enabled security realm value allow-empty-passwords must be set to false'
  tag requirements: 'B - baseline'
  tag section: 'BW.6.1.1.1'
  tag heading: 'Password Controls'

  tag action: ''

  # export JAVA_HOME=/tech/appl/java/jdk1.8.0_71 ; export JAVA=/tech/appl/java/jdk1.8.0_71/bin/java ; export PATH=$PATH:$JAVA_HOME/bin"
  # HOST_NAME => hostname
  # MGMT_HTTPS_PORT => 22005
  # $JBOSS_HOME/bin/jboss-cli.sh --connect --controller=https-remoting://$HOST_NAME:$MGMT_HTTPS_PORT --command="ls /subsystem=security/security-domain=MultipleLoginModule/authentication=classic/login-module=LdapExtended:read-attribute(name=module-options.allowEmptyPasswords)"
  #
  # Check output contains ""allowEmptyPasswords"" => ""false"""

  processes(/\/tech\/appl\/java\/.*\/bin\/java/).where { pid > 0 }.entries.each do |entry|
    java_home_str = Pathname.new(entry.command.split(' ')[0]).dirname + ".."
    java_home = java_home_str.cleanpath
    appl_host = inspec.command('hostname').stdout.chomp
    appl_port = entry.command.split(' ').select{ |word| word.include? "-Djboss.socket.binding.port-offset=" }[0].split('=')[1].to_i + 20000 + 5
    describe bash("(export JAVA_HOME=#{java_home} && export JAVA=#{java_home}/bin/java && export PATH=$PATH:#{java_home}/bin && #{JBOSS_HOME}/bin/jboss-cli.sh --connect --controller=https-remoting://#{appl_host}:#{appl_port} --command='ls /subsystem=security/security-domain=MultipleLoginModule/authentication=classic/login-module=LdapExtended:read-attribute(name=module-options.allowEmptyPasswords)')") do
      its('exit_status') { should eq 0 }
      its('stdout') { should match /\"allowEmptyPasswords\" => \"false\"/ }
    end
  end
end

control 'jboss-06' do
  impact 1.0
  title 'Entry point JARS in $INSTALLROOT$/bin'
  desc 'All the entry point JARs and start scripts included with the JBoss distribution are located in the bin directory'
  tag requirements: 'S - healthcheck and baseline'
  tag section: 'BW.1.8.2'
  tag heading: 'Protecting Resources –OSRs'
  tag action: 'Access restricted to Administrative users only'

  # find /tech/appl/chef9/jb_apps/poc-chefjb/poc-chefjb_s01/scripts/*sh
  # => user matching the process user
  # => group matching 'jbsuprt'
  # => perm 750

  processes(/\/tech\/appl\/java\/.*\/bin\/java/).where { pid > 0 }.entries.each do |entry|
    proc_user = entry.user
    scripts_dir = entry.command.split(' ').select{ |word| word.include? "-Djboss.server.base.dir=" }[0].split('=')[1] + '/scripts'
    script_dir_list = command("find #{scripts_dir} -name *.sh").stdout.split("\n")
    script_dir_list.map do |script_file|
      describe file(script_file) do
        its('owner') { should cmp "#{proc_user}" }
        its('group') { should cmp 'jbsuprt' }
        its('mode') { should cmp '0750' }
      end
    end
  end
end

control 'jboss-07' do
  impact 0.01
  title 'Data Transmission SSL'
  desc 'Encryption'
  tag requirements: 'B - baseline'
  tag section: 'BW.2.1.1.4'
  tag heading: 'Encryption'
  tag action: 'Certificates are used as per Hartford standards'

  # /usr/bin/openssl s_client -connect `hostname`:22005 < /dev/null 2> /dev/null | openssl x509 -noout -issuer -subject
  processes(/\/tech\/appl\/java\/.*\/bin\/java/).where { pid > 0 }.entries.each do |entry|
    java_home_str = Pathname.new(entry.command.split(' ')[0]).dirname + ".."
    java_home = java_home_str.cleanpath
    appl_host = inspec.command('hostname').stdout.chomp
    appl_port = entry.command.split(' ').select{ |word| word.include? "-Djboss.socket.binding.port-offset=" }[0].split('=')[1].to_i + 20000 + 5
    describe ssl(port: "#{appl_port}").protocols('tls1.2') do
      it { should be_enabled }
    end
  end
end

control 'jboss-08' do
  impact 0.7
  title 'Resources – ion'
  desc 'Production JBoss servers must not allow automatic application deployment'
  tag requirements: 'S - healthcheck and baseline'
  tag section: 'BW.6.1.8.1'
  tag heading: 'Protecting Resources - OSRs'

  # Deployment scanner must be set to false.  /subsystem=deployment-scanner/scanner=default:write-attribute(name=scan-enabled,value=false)
  #
  tag action: ''

  # export JAVA_HOME=/tech/appl/java/jdk1.8.0_71 ; export JAVA=/tech/appl/java/jdk1.8.0_71/bin/java ; export PATH=$PATH:$JAVA_HOME/bin"
  # HOST_NAME => hostname
  # MGMT_HTTPS_PORT => 22005
  # $JBOSS_HOME/bin/jboss-cli.sh --connect --controller=https-remoting://$HOST_NAME:$MGMT_HTTPS_PORT --command="/subsystem=deployment-scanner/scanner=default:read-attribute(name=scan-enabled)"
  # => expect "outcome"  => "success" and "result" => "false"
  # --command="/subsystem=datasources/data-source=*:read-attribute(name=password)"
  # => expect "outcome" => "success" and "expression" => "${VAULT::DS::ExampleDS::1)"

  processes(/\/tech\/appl\/java\/.*\/bin\/java/).where { pid > 0 }.entries.each do |entry|
    java_home_str = Pathname.new(entry.command.split(' ')[0]).dirname + ".."
    java_home = java_home_str.cleanpath
    appl_host = inspec.command('hostname').stdout.chomp
    appl_port = entry.command.split(' ').select{ |word| word.include? "-Djboss.socket.binding.port-offset=" }[0].split('=')[1].to_i + 20000 + 5
    describe bash("(export JAVA_HOME=#{java_home} && export JAVA=#{java_home}/bin/java && export PATH=$PATH:#{java_home}/bin && #{JBOSS_HOME}/bin/jboss-cli.sh --connect --controller=https-remoting://#{appl_host}:#{appl_port} --command='/subsystem=deployment-scanner/scanner=default:read-attribute(name=scan-enabled)')") do
      its('exit_status') { should eq 0 }
      its('stdout') { should match /\"result\" => false/ }
    end
    describe bash("(export JAVA_HOME=#{java_home} && export JAVA=#{java_home}/bin/java && export PATH=$PATH:#{java_home}/bin && #{JBOSS_HOME}/bin/jboss-cli.sh --connect --controller=https-remoting://#{appl_host}:#{appl_port} --command='/subsystem=datasources/data-source=*:read-attribute(name=password)')") do
      its('exit_status') { should eq 0 }
      #its('stdout') { should match /\"result\" => expression \"${VAULT::DS::ExampleDS::1}\"/ }
      its('stdout') { should match /\"result\" => expression/ }
    end
  end
end

control 'jboss-09' do
  impact 1.0
  title 'JBoss Application Server Process ID'
  desc 'A unique user ID and group should be used for this purpose. '
  tag requirements: 'S - healthcheck and baseline'
  tag section: 'BW.1.1.2.2'
  tag heading: 'Passwords'
  tag action: ''

  # the user id should belong to jbsuprt group
  processes(/\/tech\/appl\/java\/.*\/bin\/java/).where { pid > 0 }.entries.each do |entry|
    describe user(entry.user) do
      its('group') { should eq 'jbsuprt' }
    end
  end
end

control 'jboss-10' do
  impact 0.4
  title '$INSTALLROOT$'
  desc 'OSRs'
  tag requirements: 'S - healthcheck and baseline'
  tag section: 'BW.1.8.1.1'
  tag heading: 'Protecting Resources - OSRs'
  tag action: 'The $INSTALLROOT$/ and everything under it must be owned by the JBoss Application Server Process ID. The owning group must be the JBoss Application Process Group'
  tag remediation: 'update'

  # find $JVM_HOME ... all files under $JVM_HOME should belong to the process user
  processes(/\/tech\/appl\/java\/.*\/bin\/java/).where { pid > 0 }.entries.each do |entry|
    proc_user = entry.user
    scripts_dir = entry.command.split(' ').select{ |word| word.include? "-Djboss.server.base.dir=" }[0].split('=')[1] + '/scripts'
    script_dir_list = command("find #{scripts_dir} -name *.sh").stdout.split("\n")
    script_dir_list.map do |script_file|
      describe file(script_file) do
        its('owner') { should cmp "#{proc_user}" }
        its('group') { should cmp 'jbsuprt' }
      end
    end
  end
end

# End of controls
