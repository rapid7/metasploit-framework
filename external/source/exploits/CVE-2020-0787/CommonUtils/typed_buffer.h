#pragma once

#include <memory>
#include <algorithm>

template<class T>
class typed_buffer_ptr {
	std::unique_ptr<char[]> buffer_;
	size_t size_;

public:
	typed_buffer_ptr() {
	}

	explicit typed_buffer_ptr(size_t size) {
		reset(size);
	}

	void reset(size_t size) {
		buffer_.reset(new char[size]);
		memset(buffer_.get(), 0, size);
		size_ = size;
	}

	void resize(size_t size) {
		std::unique_ptr<char[]> tmp(new char[size]);

		memcpy(tmp.get(), buffer_.get(), min(size, size_));

		buffer_ = std::move(tmp);
	}

	operator T*() {
		return reinterpret_cast<T*>(buffer_.get());
	}

	operator const T*() const {
		return cget();
	}

	T* operator->() const {
		return reinterpret_cast<T*>(buffer_.get());
	}

	const T* cget() const {
		return interpret_cast<const T*>(buffer_.get());
	}

	typed_buffer_ptr(const typed_buffer_ptr<T>& other) = delete;
	typed_buffer_ptr& typed_buffer_ptr::operator=(const typed_buffer_ptr<T>& other) = delete;

	typed_buffer_ptr(typed_buffer_ptr<T>&& other) {
		buffer_ = std::move(other.buffer_);
		size_ = other.size_;
		other.size_ = 0;
	}

	typed_buffer_ptr& operator=(typed_buffer_ptr<T>&& other) {
		if (this != &other)
		{
			buffer_ = std::move(other.buffer_);
			size_ = other.size_;
			other.size_ = 0;
		}
	}

	size_t size() const {
		return size_;
	}
};