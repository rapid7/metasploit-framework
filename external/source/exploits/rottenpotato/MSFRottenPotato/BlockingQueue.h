#pragma once
#include <condition_variable>
#include <mutex>
#include <queue>
#include "stdafx.h"

typedef std::mutex Mutex;
template<typename ITEM> class BlockingQueue{
public:
	void push(const ITEM& value) { // push
		std::lock_guard<Mutex> lock(mutex);
		queue.push(std::move(value));
		condition.notify_one();
	}
	bool try_pop(ITEM& value) { // non-blocking pop
		std::lock_guard<Mutex> lock(mutex);
		if (queue.empty()) return false;
		value = std::move(queue.front());
		queue.pop();
		return true;
	}
	ITEM wait_pop() { // blocking pop
		std::unique_lock<Mutex> lock(mutex);
		condition.wait(lock, [this] {return !queue.empty(); });
		ITEM const value = std::move(queue.front());
		queue.pop();
		return value;
	}
	bool empty() const { // queue is empty?
		std::lock_guard<Mutex> lock(mutex);
		return queue.empty();
	}
	void clear() { // remove all items
		ITEM item;
		while (try_pop(item));
	}
private:
	Mutex mutex;
	std::queue<ITEM> queue;
	std::condition_variable condition;
};

