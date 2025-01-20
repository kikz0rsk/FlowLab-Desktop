#include "dnspage.h"
#include "ui_dnspage.h"

DnsPage::DnsPage(MainWindow& mainWindow, QWidget *parent)
    : QWidget(parent), ui(new Ui::DnsPage), mainWindow(mainWindow)
{
    ui->setupUi(this);
}

DnsPage::~DnsPage()
{
    delete ui;
}
