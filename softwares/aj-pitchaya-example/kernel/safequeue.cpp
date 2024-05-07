
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>
#include <signal.h>
#include <sched.h>
#include <time.h>
#include <errno.h>
#include <sys/param.h>
//#include "hdf5.h"
// Let's roll
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <netdb.h>

#include <thread>
//#include <zmq.h>
#include "dma-proxy.h"

#include <queue>

#include <queue>
#include <mutex>
#include <condition_variable>
#include <utility>

#include "zmq.h"
// A threadsafe-queue.
template <class T>
class SafeQueue
{
public:
    SafeQueue() : q(), m(), c() {}

    ~SafeQueue() {}

	
    // Add an element to the queue.
    void enqueue(T t)
    {

        std::lock_guard<std::mutex> lock(m);
		#ifdef DBG_QUEUE
		char s[1000];
		const auto p1 = std::chrono::system_clock::now();
        long long ttt =std::chrono::duration_cast<std::chrono::microseconds>(p1.time_since_epoch()).count();				
		sprintf(s,"[%s] + %d\n",keep_str(ttt,9).c_str(),total_read);
		COUT << s;
		#endif
		
        q.push(t);
        c.notify_one();
    }

    // Get the front element.
    // If the queue is empty, wait till a element is avaiable.
    T dequeue(void)
    {

        std::unique_lock<std::mutex> lock(m);
		
		#ifdef DBG_QUEUE
		char s[1000];
		const auto p1 = std::chrono::system_clock::now();
		long long ttt =std::chrono::duration_cast<std::chrono::microseconds>(p1.time_since_epoch()).count();				
		sprintf(s,"[%s] - %d\n",keep_str(ttt,9).c_str(),total_read);
		COUT << s;
        #endif

		while (q.empty())
        {
            // release lock as long as the wait and reaquire it afterwards.
            c.wait(lock);
        }
		
        T val = q.front();
        q.pop();
		
		#ifdef DBG_QUEUE
		const auto _p1 = std::chrono::system_clock::now();
		long long _ttt =std::chrono::duration_cast<std::chrono::microseconds>(_p1.time_since_epoch()).count();				
		sprintf(s,"[%s] ? %d\n",keep_str(_ttt,9).c_str(),total_read);
		COUT << s;
		#endif

        return val;
    }
	template< class Rep, class Period>
	bool wait_empty(const std::chrono::duration<Rep, Period>& rel_time) {
        std::unique_lock<std::mutex> lock(m);
        if (q.empty())
        {
            // release lock as long as the wait and reaquire it afterwards.
            c.wait_for(lock, rel_time);
        }
		return q.empty();
	}
    int size() {
	std::unique_lock<std::mutex> lock(m);
        return q.size();
    }
    bool empty() {
		std::unique_lock<std::mutex> lock(m);
		return q.empty();
    }

private:
    std::queue<T> q;
    mutable std::mutex m;
    std::condition_variable c;
};