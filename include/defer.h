#pragma once

#include <utility>

template<typename T>
class Defer {
	T func;

	public:
		Defer(T&& func) : func(std::move(func)) {}
		~Defer() { func(); }
};
