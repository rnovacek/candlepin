# This script is used to create a given number of consumers in threads and
# have them all attempt to consume from the pools for a particular product.
#
# TO RUN:
# in terminal 1: touch logout
# in terminal 1: tail -f logout
# in terminal 2: ruby concurrency-test.rb 40 2> logout
# watch the progress bar in terminal 2 (green dot for consumed ent, red N for not)
# watch the details in terminal 1

require "../client/ruby/candlepin_api"
require 'pp'
require 'optparse'

CP_SERVER = "grimlock.usersys.redhat.com"
CP_PORT = 8443
CP_NOSSL_PORT = 8080
CP_ADMIN_USER = "admin"
CP_ADMIN_PASS = "admin"

def debug(msg)
    STDERR.write Thread.current[:name]
    STDERR.write " :: "
    STDERR.write msg
    STDERR.write "\n"
    STDERR.flush
end

def no_ent()
    return "\033[31mN\033[0m"
end

def an_ent()
    return "\033[32m.\033[0m"
end


def consume(consumer_cp, pool_id)
  #debug "consume"
  #debug consumer['id']
  debug consumer_cp
#  consumer_cp = Candlepin.new(nil, nil, consumer['idCert']['cert'],
#                             consumer['idCert']['key'], server, port)
#  consumer_cp = Candlepin.new(nil, nil, nil, nil, server, port,
#                             uuid=consumer['uuid'], use_ssl=false)
  #debug consumer_cp
  ent = consumer_cp.consume_pool(pool_id)[0]
  pool = consumer_cp.get_pool(ent['pool']['id'])
  #debug "Got entitlement #{ent['id']} from pool #{ent['pool']['id']} (#{pool['consumed']} of #{pool['quantity']})"
  pool = nil
  return ent, pool
end

def serials(consumer_cp)
  #consumer_cp = Candlepin.new(nil, nil, consumer['idCert']['cert'],
  #                           consumer['idCert']['key'], server, port)
   
  ret = consumer_cp.list_certificate_serials()
  debug ret
  return "sdfsd"
end

def register(server, port, user, pass, owner_key)
  cp = Candlepin.new(username=user, password=pass,
    cert=nil, key=nil,
    host=server, port=port)
  consumer = cp.register("test" << rand(10000).to_s, :candlepin, nil, {}, nil, owner_key)

  consumer_cp = Candlepin.new(nil, nil, consumer['idCert']['cert'],
                             consumer['idCert']['key'], server, port)
  #debug consumer['id']
  return consumer_cp
end

#  cp = Candlepin.new(nil, nil, consumer['idCert']['cert'],
#                     consumer['idCert']['key'], server, port)
#  ent = cp.consume_pool(pool_id)[0]
#  pool = cp.get_pool(ent['pool']['id'])

#  # Now unbind it:
#  cp.unbind_entitlement(ent['id'], {:uuid => consumer['uuid']})
#  debug "Got and returned entitlement: #{ent['id']}"
#  return ent
#end

debug 'creating product'
# Create a product and pool to consume:
product_id = "concurproduct-#{rand(100000)}"

cp = Candlepin.new(username=CP_ADMIN_USER, password=CP_ADMIN_PASS,
  cert=nil, key=nil,
  host=CP_SERVER, port=CP_PORT)

test_owner = cp.create_owner("testowner-#{rand(100000)}")
puts "create owner"

attributes = {'multi-entitlement' => "yes"}
cp.create_product(product_id, product_id, {:attributes => attributes})
puts "create_product"

cp.create_subscription(test_owner['key'], product_id, 500)
puts "start refresh pools"
cp.refresh_pools(test_owner['key'])
pools = cp.list_pools(:owner => test_owner['id'])
pool = pools[0]

# Create a consumer to bind entitlements to. We'll just use one combined
# with a pool that supports multi-entitlement:
#consumer = cp.register("test" << rand(10000).to_s, :candlepin,
#  nil, {}, nil, test_owner['key'])
#consumer_cp = Candlepin.new(nil, nil, consumer['idCert']['cert'],
#  consumer['idCert']['key'], CP_SERVER, CP_PORT)

# Launch threads to try to bind at same time:
num_threads = ARGV[0].to_i
if num_threads == 0
  num_threads = 1
end

queue = Queue.new

threads = []
consumers = []
for i in 0..num_threads - 1
  threads[i] = Thread.new do
    Thread.current[:name] = "Thread"
    begin
      consumer_cp = register(CP_SERVER, CP_PORT, CP_ADMIN_USER, CP_ADMIN_PASS,
                          test_owner['key'])
      queue << consumer_cp
    rescue
      debug "Exception caught / no entitlement"
      raise
      #      queue << no_ent
    end
  end
end


collector = Thread.new do
  for i in 0..num_threads - 1
    consumer_cp << queue.pop
    STDOUT.print "."
    STDOUT.flush
    Thread.new do
        begin
            consumed = consumer(consumer_cp, pool['id'])
            queue << consumed
        rescue
            debug "wtf"
            queue << "consume failed"
        end
    end
end
   # Thread.new do
   # begin
    #    serial = serials(consumer_cp)
    #    queue << serial;
    #rescue
    #    debug "wtf"
  #      queue << "serial failed"
 #   end
#
#    end
#  STDOUT.print "\n"
#end

debug "collector1"
collector.join
threads.each { |thread| thread.join }

debug "joined"
#puts consumers

debug "pool"
#debug pool['id']
queue = Queue.new


#ent = consume(CP_SERVER, CP_PORT, consumers[0], pool['id'])
#debug ent



debug 'foo'
threads = []
for i in 0..num_threads - 1
  threads[i] = Thread.new do
    Thread.current[:name] = "Thread"
    begin
      ent = consume(CP_SERVER, CP_PORT, consumers[i], pool['id'])
      debug "post consume"
      queue << (ent.nil? ? no_ent : an_ent)
    #end
    rescue
      #debug consumers[i]['uuid']
      debug "Exception caught, something in consume"
      #raise
      queue << no_ent
    end
    begin
       debug "fooffff"
       serials = serials(CP_SERVER, CP_PORT, consumers[i])
       queue << serials
    rescue
       debug "bar"
    end
  end
end


debug queue.length
debug "collector2"
collector = Thread.new do
  res_string = ""
  for i in 0..num_threads - 1
    STDOUT.print "#{i}"
    STDOUT.flush
    res_string << queue.pop
    STDOUT.print "\r" + res_string
    STDOUT.flush
  end
  STDOUT.print "\n"
end

debug queue
collector.join
threads.each { |thread| thread.join }
