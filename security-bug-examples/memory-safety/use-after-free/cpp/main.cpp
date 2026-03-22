#include <iostream>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <functional>
#include <sstream>

struct Document {
    int id;
    char title[128];
    char *content;
    size_t content_len;
};

class DocumentStore {
public:
    DocumentStore() : count_(0), capacity_(16) {
        docs_ = new Document*[capacity_];
        std::memset(docs_, 0, capacity_ * sizeof(Document*));
    }

    ~DocumentStore() {
        for (int i = 0; i < count_; i++) {
            if (docs_[i]) {
                free(docs_[i]->content);
                delete docs_[i];
            }
        }
        delete[] docs_;
    }

    int add(int id, const char *title, const char *content) {
        if (count_ >= capacity_) return -1;
        Document *doc = new Document;
        doc->id = id;
        std::strncpy(doc->title, title, sizeof(doc->title) - 1);
        doc->title[sizeof(doc->title) - 1] = '\0';
        doc->content_len = std::strlen(content);
        doc->content = (char *)std::malloc(doc->content_len + 1);
        std::strcpy(doc->content, content);
        docs_[count_] = doc;
        count_++;
        return count_ - 1;
    }

    Document *get(int index) {
        if (index < 0 || index >= count_) return nullptr;
        return docs_[index];
    }

    void remove(int index) {
        if (index < 0 || index >= count_) return;
        free(docs_[index]->content);
        delete docs_[index];
        for (int i = index; i < count_ - 1; i++) {
            docs_[i] = docs_[i + 1];
        }
        docs_[count_ - 1] = nullptr;
        count_--;
    }

    int count() const { return count_; }

    void print_all() const {
        std::cout << "Documents (" << count_ << "):" << std::endl;
        for (int i = 0; i < count_; i++) {
            std::cout << "  [" << docs_[i]->id << "] "
                      << docs_[i]->title << " ("
                      << docs_[i]->content_len << " bytes)" << std::endl;
        }
    }

private:
    Document **docs_;
    int count_;
    int capacity_;
};

class EventBus {
public:
    struct Listener {
        Document *doc;
        std::function<void(Document *)> handler;
    };

    void subscribe(Document *doc, std::function<void(Document *)> handler) {
        listeners_.push_back({doc, handler});
    }

    void publish() {
        for (auto &listener : listeners_) {
            if (listener.doc) {
                listener.handler(listener.doc);
            }
        }
    }

    void clear() { listeners_.clear(); }

private:
    std::vector<Listener> listeners_;
};

static void print_document_event(Document *doc) {
    std::cout << "  Event for doc " << doc->id << ": " << doc->title << std::endl;
}

static Document *fetch_and_release(DocumentStore &store, int index) {
    Document *doc = store.get(index);
    if (!doc) return nullptr;

    Document *snapshot = new Document;
    snapshot->id = doc->id;
    std::strcpy(snapshot->title, doc->title);
    snapshot->content_len = doc->content_len;
    snapshot->content = doc->content;

    store.remove(index);

    return snapshot;
}

static char *merge_contents(DocumentStore &store) {
    size_t total = 0;
    for (int i = 0; i < store.count(); i++) {
        Document *d = store.get(i);
        total += d->content_len + 1;
    }

    char *merged = (char *)std::malloc(total + 1);
    if (!merged) return nullptr;

    size_t offset = 0;
    for (int i = 0; i < store.count(); i++) {
        Document *d = store.get(i);
        std::memcpy(merged + offset, d->content, d->content_len);
        offset += d->content_len;
        merged[offset] = '\n';
        offset++;
    }
    merged[offset] = '\0';
    return merged;
}

static char *resize_buffer(char *buf, size_t old_size, size_t new_size) {
    char *new_buf = (char *)std::realloc(buf, new_size);
    if (!new_buf) {
        std::cout << "Realloc failed, old buffer at: " << (void *)buf << std::endl;
        std::free(buf);
        return nullptr;
    }
    return new_buf;
}

static void build_index(DocumentStore &store) {
    size_t buf_size = 64;
    char *index_buf = (char *)std::malloc(buf_size);
    if (!index_buf) return;

    int offset = std::snprintf(index_buf, buf_size, "Index:\n");

    for (int i = 0; i < store.count(); i++) {
        Document *d = store.get(i);
        int needed = std::snprintf(nullptr, 0, "  %d: %s\n", d->id, d->title);

        if (offset + needed + 1 > (int)buf_size) {
            char *old_buf = index_buf;
            buf_size = (offset + needed + 1) * 2;
            index_buf = resize_buffer(index_buf, buf_size / 2, buf_size);
            if (!index_buf) {
                std::cout << "Using stale buffer after failed realloc" << std::endl;
                std::cout << old_buf << std::endl;
                return;
            }
        }

        offset += std::snprintf(index_buf + offset, buf_size - offset,
                                "  %d: %s\n", d->id, d->title);
    }

    std::cout << index_buf;
    std::free(index_buf);
}

static void demo_dangling_after_remove(DocumentStore &store) {
    Document *ref = store.get(1);
    std::cout << "Before remove - doc: " << ref->title << std::endl;

    store.remove(1);

    std::cout << "After remove - doc: " << ref->title << std::endl;
    std::cout << "After remove - content length: " << ref->content_len << std::endl;
}

static void demo_event_bus(DocumentStore &store) {
    EventBus bus;

    bus.subscribe(store.get(0), print_document_event);
    bus.subscribe(store.get(1), print_document_event);
    bus.subscribe(store.get(2), print_document_event);

    store.remove(1);

    std::cout << "Publishing events after removal:" << std::endl;
    bus.publish();
    bus.clear();
}

static void demo_snapshot(DocumentStore &store) {
    Document *snap = fetch_and_release(store, 0);
    if (snap) {
        std::cout << "Snapshot: " << snap->title << std::endl;
        std::cout << "Snapshot content: " << snap->content << std::endl;
        std::free(snap->content);
        delete snap;
    }
}

static void demo_double_free(DocumentStore &store) {
    if (store.count() < 2) return;

    Document *d = store.get(0);
    char *content_ptr = d->content;

    store.remove(0);

    std::free(content_ptr);
    std::cout << "Released content buffer" << std::endl;
}

static void populate_store(DocumentStore &store) {
    store.add(101, "architecture_overview", "This document describes the system architecture and component interactions.");
    store.add(102, "api_specification", "RESTful API endpoints for the document management service.");
    store.add(103, "deployment_guide", "Step-by-step instructions for deploying to production environments.");
    store.add(104, "performance_report", "Benchmark results and optimization recommendations for Q4.");
    store.add(105, "onboarding_manual", "New team member onboarding procedures and resource links.");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <mode>" << std::endl;
        std::cout << "Modes:" << std::endl;
        std::cout << "  dangling     Access document after removal" << std::endl;
        std::cout << "  events       Fire events for removed documents" << std::endl;
        std::cout << "  snapshot     Fetch document snapshot" << std::endl;
        std::cout << "  doublefree   Double free document content" << std::endl;
        std::cout << "  index        Build document index" << std::endl;
        std::cout << "  merge        Merge all document contents" << std::endl;
        std::cout << "  list         List all documents" << std::endl;
        return 0;
    }

    std::string mode(argv[1]);
    DocumentStore store;
    populate_store(store);

    if (mode == "dangling") {
        demo_dangling_after_remove(store);
    } else if (mode == "events") {
        demo_event_bus(store);
    } else if (mode == "snapshot") {
        demo_snapshot(store);
    } else if (mode == "doublefree") {
        demo_double_free(store);
    } else if (mode == "index") {
        build_index(store);
    } else if (mode == "merge") {
        char *merged = merge_contents(store);
        if (merged) {
            std::cout << merged;
            std::free(merged);
        }
    } else if (mode == "list") {
        store.print_all();
    } else {
        std::cerr << "Unknown mode: " << mode << std::endl;
        return 1;
    }

    return 0;
}
