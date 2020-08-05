#include "fileeventstableplugin.h"

#include <chrono>
#include <mutex>

namespace zeek {
struct FileEventsTablePlugin::PrivateData final {
  PrivateData(IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : configuration(configuration_), logger(logger_) {}

  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  RowList row_list;
  std::mutex row_list_mutex;
  std::size_t max_queued_row_count{0U};
};

Status FileEventsTablePlugin::create(Ref &obj,
                                     IZeekConfiguration &configuration,
                                     IZeekLogger &logger) {
  obj.reset();

  try {
    auto ptr = new FileEventsTablePlugin(configuration, logger);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

FileEventsTablePlugin::~FileEventsTablePlugin() {}

const std::string &FileEventsTablePlugin::name() const {
  static const std::string kTableName{"file_events"};

  return kTableName;
}

const FileEventsTablePlugin::Schema &FileEventsTablePlugin::schema() const {
  // clang-format off
  static const Schema kTableSchema = {
    { "action", IVirtualTable::ColumnType::String },
    { "pid", IVirtualTable::ColumnType::Integer },
    { "path", IVirtualTable::ColumnType::String },
    { "file_path", IVirtualTable::ColumnType::String },
    { "inode", IVirtualTable::ColumnType::String },
    { "auid", IVirtualTable::ColumnType::Integer },
    { "success", IVirtualTable::ColumnType::Integer },
    { "time", IVirtualTable::ColumnType::Integer }
  };
  // clang-format on

  return kTableSchema;
}

Status FileEventsTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status FileEventsTablePlugin::processEvents(
    const IAudispConsumer::AuditEventList &event_list) {
  RowList generated_row_list;

  for (const auto &audit_event : event_list) {
    Row row;

    auto status = generateRow(row, audit_event);
    if (!status.succeeded()) {
      return status;
    }

    if (!row.empty()) {
      generated_row_list.push_back(std::move(row));
    }
  }

  {
    std::lock_guard<std::mutex> lock(d->row_list_mutex);

    // clang-format off
    d->row_list.insert(
      d->row_list.end(),
      std::make_move_iterator(generated_row_list.begin()),
      std::make_move_iterator(generated_row_list.end())
    );
    // clang-format on

    if (d->row_list.size() > d->max_queued_row_count) {
      auto rows_to_remove = d->row_list.size() - d->max_queued_row_count;

      d->logger.logMessage(IZeekLogger::Severity::Warning,
                           "file_events: Dropping " +
                               std::to_string(rows_to_remove) +
                               " rows (max row count is set to " +
                               std::to_string(d->max_queued_row_count));

      // clang-format off
      d->row_list.erase(
        d->row_list.begin(),
        std::next(d->row_list.begin(), rows_to_remove)
      );
      // clang-format on
    }
  }

  return Status::success();
}

FileEventsTablePlugin::FileEventsTablePlugin(IZeekConfiguration &configuration,
                                             IZeekLogger &logger)
    : d(new PrivateData(configuration, logger)) {

  d->max_queued_row_count = d->configuration.maxQueuedRowCount();
}

Status FileEventsTablePlugin::generateRow(
    Row &row, const IAudispConsumer::AuditEvent &audit_event) {
  row = {};

  std::string action;
  switch (audit_event.syscall_data.type) {
  case IAudispConsumer::SyscallRecordData::Type::Open:
    action = "open";
    break;

  case IAudispConsumer::SyscallRecordData::Type::OpenAt:
    action = "openat";
    break;

  case IAudispConsumer::SyscallRecordData::Type::Create:
    action = "create";
    break;

  default:
    return Status::success();
  }

  if (!audit_event.cwd_data.has_value()) {
    return Status::failure("Missing an AUDIT_CWD record from a file event ");
  }

  if (!audit_event.path_data.has_value()) {
    return Status::failure("Missing an AUDIT_PATH record from a file event");
  }

  const auto &path_record = audit_event.path_data.value();
  const auto &last_path_entry = path_record.front();

  const auto &syscall_data = audit_event.syscall_data;

  row["action"] = action;
  row["pid"] = syscall_data.process_id;
  row["path"] = syscall_data.exe;
  row["auid"] = syscall_data.auid;
  row["success"] =
      static_cast<std::int64_t>(audit_event.syscall_data.succeeded ? 1 : 0);

  auto current_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch());

  row["time"] = static_cast<std::int64_t>(current_timestamp.count());
  row["file_path"] = last_path_entry.path;
  row["inode"] = last_path_entry.inode;

  return Status::success();
}
} // namespace zeek
