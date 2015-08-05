#ifndef REMFILE_H
#define REMFILE_H

#include <QFile>

class RemFile
{
private:
    RemFile();
public:
    // remove file "fileName"
    static bool removeFile(std::string fileName)
    {
        return QFile(QString::fromStdString(fileName)).remove();
    }
};

#endif
