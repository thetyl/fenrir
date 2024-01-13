# Fenrir

Web Socket C++ server.

### Usage

```c++
#include "fenrir.h"

using namespace fenrir;

struct Job {
	std::string title;
	double hours;
};

struct Person {
	std::string name;
	bool isAlive;
	int age;
	Job currentJob;
	std::vector<Job> jobs;
};

void to_json(Json &json, Job &job) {
	json_begin(json);
	to_json(json, "title", job.title);
	to_json(json, "hours", job.hours);
	json_end(json);
}

void to_json(Json &json, Person &person) {
	json_begin(json);
	to_json(json, "name", person.name);
	to_json(json, "isAlive", person.isAlive);
	to_json(json, "age", person.age);
	to_json(json, "currentJob", person.currentJob);
	to_json(json, "jobs", person.jobs);
	json_end(json);
}

void from_json(JsonElement &json, Job &job) {
	from_json(json, "title", job.title);
	from_json(json, "hours", job.hours);
}

void from_json(JsonElement &json, Person &person) {
	from_json(json, "name", person.name);
	from_json(json, "isAlive", person.isAlive);
	from_json(json, "age", person.age);
	from_json(json, "currentJob", person.currentJob);
	from_json(json, "jobs", person.jobs);
}

void on_socket_connect(SOCKET_ID socket_id) {
	std::cout << "Client connected: " << socket_id << std::endl;

	Person person;
	person.name = "Tyl";
	person.isAlive = true;
	person.age = 78;
	person.currentJob.title = "Current Job";
	person.currentJob.hours = 124.53;

	{
		Job &job = person.jobs.emplace_back();
		job.title = "Job A";
		job.hours = 40.3;
	}

	{
		Job &job = person.jobs.emplace_back();
		job.title = "Job B";
		job.hours = 20.56;
	}

	send(socket_id, to_json(person));
}

void on_socket_message(SOCKET_ID socket_id, const std::string &data) {
	std::cout << "Message: " << socket_id << " = " << data << std::endl;

	JsonElement *json = from_json(data);

	Person person;
	from_json(*json, person);

	free_json(json);
}

void on_socket_disconnect(SOCKET_ID socket_id) {
	std::cout << "Client disconnected: " << socket_id << std::endl;
}

int main() {
	ServerDesc server;
	server.port = 8472;
	server.on_connect = on_socket_connect;
	server.on_message = on_socket_message;
	server.on_disconnect = on_socket_disconnect;

	listen(server);

	return 0;
}
```
