#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>
#include <sys/unistd.h>
#include <string>
#include <map>
#include <sstream>
#include <atomic>
#include <iostream>
#include <string>

boost::mutex global_stream_lock;

void WorkerThread( boost::shared_ptr< boost::asio::io_service > io_service ) {
    global_stream_lock.lock();
    std::cout << "[" << boost::this_thread::get_id()
              << "] Thread Start" << std::endl;
    global_stream_lock.unlock();

    while( true ) {
        try {
            boost::system::error_code ec;
            io_service->run( ec );
            if( ec ) {
                global_stream_lock.lock();
                std::cout << "[" << boost::this_thread::get_id()
                          << "] Error: " << __FUNCTION__ << " " << ec << std::endl;
                global_stream_lock.unlock();
            }
            break;
        } catch( std::exception & ex ) {
            global_stream_lock.lock();
            std::cout << "[" << boost::this_thread::get_id()
                      << "] Exception: " << __FUNCTION__ << " " << ex.what() << std::endl;
            global_stream_lock.unlock();
        }
    }

    global_stream_lock.lock();
    std::cout << "[" << boost::this_thread::get_id()
              << "] Thread Finish" << std::endl;
    global_stream_lock.unlock();
}

static FILE * popen2(  char * args[], const char * type, pid_t & pid  ) {
    enum { READ, WRITE } ;
    pid_t child_pid;
    int fd[2];
    pipe(fd);

    if((child_pid = fork()) == -1) {
        perror("fork");
        exit(1);
    } // if

    if (child_pid == 0) {
        if (type == "r") {
            close(fd[READ]);    //Close the READ end of the pipe since the child's fd is write-only
            dup2(fd[WRITE], 2); //Redirect stdout to pipe
        } // if
        else {
            close(fd[WRITE]);    //Close the WRITE end of the pipe since the child's fd is read-only
            dup2(fd[READ], 0);   //Redirect stdin to pipe
        } // else

        execvp( args[ 0 ], args );
        exit(0);
    } // if
    else {
        if (type == "r") {
            close(fd[WRITE]); //Close the WRITE end of the pipe since parent's fd is read-only
        } // if
        else {
            close(fd[READ]); //Close the READ end of the pipe since parent's fd is write-only
        }   // else
    } // else

    pid = child_pid;

    if (type == "r")
        return fdopen(fd[READ], "r");
    else
        return fdopen(fd[WRITE], "w");
} // popen2()

class BASIC_NetworkObject {
  public :
    BASIC_NetworkObject( boost::asio::io_service * io_service, int _pN, const char * _oN ) {
      myAcceptor = new boost::asio::ip::tcp::acceptor( *io_service ) ;
      mySocket = new boost::asio::ip::tcp::socket( *io_service ) ;
      portNum = _pN ;
      strncpy( objName, _oN, 32 ) ;
      memset( buffer, '\0', 256 ) ;
    } // BASIC_NetworkObject()

    ~BASIC_NetworkObject() {
      std::cout << objName << "[" << boost::this_thread::get_id()
                << "] network service is closing......" << std::endl ;
      myAcceptor->close( );
    	mySocket->shutdown( boost::asio::ip::tcp::socket::shutdown_both );
    	mySocket->close( );
    } // ~BASIC_NetworkObject()
  protected :
    boost::asio::ip::tcp::acceptor * myAcceptor = NULL ;
    boost::asio::ip::tcp::socket * mySocket = NULL ;
    char objName[ 32 ] ;
    char buffer[ 256 ] ;
    int portNum = 0 ;
} ;

class DataCollector : public BASIC_NetworkObject {
  public :
    std::map<std::string,int> deviceList ;
    std::atomic<bool> isWriting, isReading ;

    DataCollector( boost::asio::io_service * io_service, int _pN ) : BASIC_NetworkObject( io_service, _pN, "dataCollector" ) {
      isWriting = false ;
      isReading = false ;

      boost::asio::ip::tcp::resolver resolver( *io_service );
      boost::asio::ip::tcp::resolver::query query(
        boost::asio::ip::tcp::v4(),
        boost::lexical_cast< std::string >( portNum )
      );

      boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve( query );
      myAcceptor->open( endpoint.protocol() );
      myAcceptor->set_option( boost::asio::ip::tcp::acceptor::reuse_address( false ) );
      myAcceptor->bind( endpoint );

      myAcceptor->listen( boost::asio::socket_base::max_connections );
      myAcceptor->accept( *mySocket ) ;

      ReciveInfo() ;
      std::cout << "Working under " << parentMAC << "@" << targetChannel << std::endl ;

    } // DataCollector

    void StartMoniting() {
      controller_threads.create_thread( boost::bind( &DataCollector::MonitingThread, this ) );
    } // StartMoniting()

    void MonitingThread() {
      char * args[] = {
        "airodump-ng",
        "--channel",
        targetChannel,
        "--bssid",
        parentMAC,
        "mon0",
        NULL
      } ;

      pid_t porcessid ;
      FILE * fd = popen2( args, "r", porcessid ) ;

      boost::regex expr{"\\s*((([A-Fa-f0-9]{2}):){5}([A-Fa-f0-9]{2})\\s+){2}(\\-\\d+\\s+)[\\-\\w\\s]*"};
      boost::smatch what;

      char buf[ 512 ] = "" ;
      while ( !returnFlag ) {
        fgets( buf, 512, fd ) ;
        std::cout << buf ;
        if ( boost::regex_search( std::string(buf), what, expr) ) {
          char * pch = NULL, * macAddr = NULL ;
          pch = strtok( buf, " " ) ;
          for ( int i = 0 ; pch != NULL ; ++i ) {
            if ( i == 1 )
              macAddr = pch ;
            else if ( i == 2 && deviceList[ std::string( macAddr ) ] != atoi( pch ) ) {
              while ( isReading ) ;

              isWriting = true ;
              deviceList[ std::string( macAddr ) ] = atoi( pch ) ;
              isWriting = false ;
            } // else if

            pch = strtok( NULL, " " ) ;
          } // for
        } // if

        memset( buf, '\0', 512 ) ;
      } // while

      return ;
    } // StartMoniting()

    ~DataCollector() {
      returnFlag = true ;
      std::cout << "Waiting for all controller threads end....." << std::endl ;
      controller_threads.join_all() ;
      std::cout << "DataCollector exit......" << std::endl ;
    } // ~DataCollector()

  private :
    char * parentMAC = NULL ;
    char * targetChannel = NULL ;
    bool returnFlag = false ;
    boost::thread_group controller_threads ;

    void ReciveInfo() {
      mySocket->receive( boost::asio::buffer( buffer ) ) ;
      char * pch = NULL ;

      pch = strtok( buffer, "," ) ;
      while( pch != NULL ) {
        if ( parentMAC == NULL )
          parentMAC = pch ;
        else
          targetChannel = pch ;
        pch = strtok( NULL, "," ) ;
      } // while
    } // ReciveInfo()
} ;

DataCollector * dc = NULL ;
class NetworkManager : public BASIC_NetworkObject  {
  private :
    void BufClear( boost::system::error_code ec, bool * sockOK ) {
      if ( ec ) {
        std::cout << boost::this_thread::get_id() << " " << ec << std::endl ;
        *sockOK = false ;
        // exit( ec.value() ) ;
      } // if
      return ;
    } // BufClear()
  public :
    NetworkManager( boost::asio::io_service * io_service, int _pN ) : BASIC_NetworkObject( io_service, _pN, "NetworkManager" ) {

    } //NetworkManager()

    void OnAccept( boost::shared_ptr<boost::asio::ip::tcp::socket> sock ) {

      boost::shared_ptr<boost::asio::ip::tcp::socket> newSock( new boost::asio::ip::tcp::socket( sock->get_io_service() ) ) ;
      myAcceptor->listen() ;
      myAcceptor->async_accept( *newSock, boost::bind( &NetworkManager::OnAccept, this, newSock ) ) ;

      //std::cout << "G" << std::endl ;
      std::map<std::string,int> tempList ;
      //std::cout << "F" << std::endl ;

      int i = 0 ;

      bool socketOK = true ;

      std::stringstream ss ;
      while ( socketOK ) {
        while ( dc->isWriting ) ;
        dc->isReading = true ;
        tempList = dc->deviceList ;
        dc->isReading = false ;

        for ( auto it = tempList.begin() ; it != tempList.end() ; ++it ) {
          ss << it->first << " " << it->second << std::endl ;
        } // for

        //std::cout << "D" << std::endl ;
        sock->send( boost::asio::buffer( ss.str() ) ) ;
        ss.str( "" ) ;
        //std::cout << "E" << std::endl ;

        // boost::this_thread::sleep( boost::posix_time::milliseconds(100) ) ;
      } // while
    } // OnAccept()

    void StartAConnection( boost::asio::ip::tcp::resolver::query infoQ,
                           boost::asio::io_service * io_service
                         ) {

      boost::asio::ip::tcp::resolver resolver( *io_service );
      boost::asio::ip::tcp::endpoint ed = *resolver.resolve( infoQ ) ;
      myAcceptor->open( ed.protocol() );
      myAcceptor->set_option( boost::asio::ip::tcp::acceptor::reuse_address( false ) );
      myAcceptor->bind( ed );

      myAcceptor->listen( boost::asio::socket_base::max_connections );

      boost::shared_ptr<boost::asio::ip::tcp::socket> newSock( new boost::asio::ip::tcp::socket( *io_service ) ) ;
      myAcceptor->async_accept( *newSock, boost::bind( &NetworkManager::OnAccept, this, newSock ) ) ;
    } // StartAConnection()
}; // NetworkManager

int main( int argc, char * argv[] ) {

    	boost::shared_ptr< boost::asio::io_service > io_service(
    		new boost::asio::io_service
    		);
    	boost::shared_ptr< boost::asio::io_service::work > work(
    		new boost::asio::io_service::work( *io_service )
    		);
    	boost::shared_ptr< boost::asio::io_service::strand > strand(
    		new boost::asio::io_service::strand( *io_service )
    		);

    	global_stream_lock.lock();
    	std::cout << "[" << boost::this_thread::get_id()
    		<< "] Press [return] to exit." << std::endl;
    	global_stream_lock.unlock();

    	boost::thread_group worker_threads;
    	for( int x = 0; x < 10; ++x )
    	{
    		worker_threads.create_thread( boost::bind( &WorkerThread, io_service ) );
    	}

    dc = new DataCollector( io_service.get(), 48763 ) ;
    dc->StartMoniting() ;
    NetworkManager nm( io_service.get(), 13768 ) ;

    boost::asio::ip::tcp::resolver resolver( *io_service );
    boost::asio::ip::tcp::resolver::query query(
      boost::asio::ip::tcp::v4(),
      boost::lexical_cast< std::string >( 13768 )
    );

    nm.StartAConnection( query, io_service.get() );
    worker_threads.join_all() ;
    return 0;
}
