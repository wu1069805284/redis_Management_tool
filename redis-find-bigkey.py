#!/usr/bin/env python

import redis,sys,os,time
import rediscluster
from optparse import OptionParser

def get_cli_options():
    parser = OptionParser(usage="usage: python %prog [options]",
            description="""Desc: Show redis bigkeys""")

    parser.add_option("-H", "--host",
                        dest="host",
                        metavar="HOST",
                        help="Redis host")
    parser.add_option("-P", "--port",
                        dest="port",
                        metavar="PORT",
                        help="Redis port")
    parser.add_option("-p","--password",
			            dest="pwd",
			            metavar="Password",
			            default='',
			            help="Redis password")
    parser.add_option("-d", "--dbs",
                        dest="db",
                        metavar="DB",
			            default=0,
                        help="Redis dbname")

    (options, args) = parser.parse_args()
    if not options.host or not options.port:
        parser.error("incorrect number of arguments")

    return options



def redis_cluster_conn(rhost,rport):
	startup_nodes=[{"host":rhost,"port":rport}]
	rc=redis.RedisCluster(startup_nodes=startup_nodes,max_connections=100,\
		decode_responses=True, readonly_mode=True)
	return rc


def redis_instance_conn(rhost,rport,rpwd=None,rdb=0):
	r=redis.StrictRedis(host=rhost,port=rport,password=rpwd,db=rdb)
	return r


def write_file(fileName,content_iterable):
    try:
        pwd = open(fileName,'a')
        for key,value in content_iterable.items():
            pwd.write(key+':'+value+'\t')
	pwd.write('\n')
    finally:
        pwd.close()


def Initialization_file(filetype):
	filename=sys.path[0] + '/' + time.strftime('%Y%m%d') + filetype + '.log'	
	if os.path.exists(filename):
		open(filename,'w')
	return filename			


def check_big_key(f, n, r, k):

  bigKey = False
  length = 0 

  try:
    type = r.type(k)
    if type == "string":
      length = r.strlen(k)
    elif type == "hash":
      length = r.hlen(k)
    elif type == "list":
      length = r.llen(k)
    elif type == "set":
      length = r.scard(k)
    elif type == "zset":
      length = r.zcard(k)
  except:
    return
  
  if length > 5120:
    bigKey = True

  if bigKey :

    dic = { "byte" : str(length),
	    "key" : k,
            "type" : str(type),  
	    "number" : str(n+1)
	}

    write_file(f,dic)


def check_redis(rhost,rport,rpwd=None,rdb=0):
	try:
		rconn=redis_instance_conn(rhost,rport,rpwd,rdb)
		rv=check_redis_version(rconn)
		redis_mode=rconn.info()['redis_mode']
		if rv is True:
			if redis_mode == 'cluster':
				return 1
			elif redis_mode == 'standalone':
				return 0
			else:
				print 'Redis node %s:%s is not cluster or standalone' %(rhost,rport)
				sys.exit(-1)
	except ConnectionError as e:
		sys.stderr.write('Could not connect to Redis Server : %s\n' % e)
		sys.exit(-1)
	except ResponseError as e:
		sys.stderr.write('Could not connect to Redis Server : %s\n' % e)
		sys.exit(-1)

	

def r_instance(rhost,rport,rpwd=None,rdb=0):
	rconn=redis_instance_conn(rhost,rport,rpwd,rdb)
	name='_instance_bigkey_' + rport
	filename=Initialization_file(name)
	for num,k in enumerate(rconn.scan_iter(count=10000)):
		check_big_key(filename,num,rconn, k)



def r_cluster(rhost,rport):
	rcc=redis_cluster_conn(rhost,rport)
	name='_cluster_bigkey_' + rport
	filename=Initialization_file(name)
	for num,k in enumerate(rcc.scan_iter(count=10000)):
		check_big_key(filename,num,rcc, k)


def check_redis_version(redis):
    server_info = redis.info()
    version_str = server_info['redis_version']
    version = tuple(map(int, version_str.split('.')))

    if version[0] > 2 or (version[0] == 2 and version[1] > 8) :
        return True
    elif version[0] == 2 and version[1] < 8:
	    raise Exception("The instance version is less than 2.8 ",version)



if __name__ == '__main__':

	options=get_cli_options()
	if len(sys.argv) < 3:
		print 'Usage: python ', sys.argv[0], ' host port '	
		exit(1)

	if options.pwd:
		if check_redis(options.host,options.port,options.pwd,options.db) == 0:
			r_instance(options.host,options.port,options.pwd,options.db)
	
		if check_redis(options.host,options.port,options.pwd,options.db) == 1:
				print "Redis cluster cannot be certified"
	else:
		if check_redis(options.host,options.port,options.db) == 0:
			r_instance(options.host,options.port,options.db)
		elif check_redis(options.host,options.port,options.db) == 1:
			r_cluster(options.host,options.port,options.db)
